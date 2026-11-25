//! The proxy's exchange as machines without I/O (SID 0016).
//!
//! The blocking relays of this crate read and write sockets. An event loop cannot wait in
//! them. The machines here do the same protocol work on bytes the caller already holds:
//! [`encode_request`] writes the origin request, [`UploadRelay`] frames the rest of a request
//! body, and [`ResponseRelay`] turns origin bytes into client bytes. Each consumes input and
//! appends output. None reads a socket, keeps time or holds a buffer of its own.
//!
//! The machines call the helpers the blocking relays call (the head parser, the field
//! writers, the chunk checks, the upgrade checks), and the tests compare both on the same
//! bytes. The rules for keeping a client connection and pooling an origin socket are those
//! of [`crate::stream_proxy`].

use sibuna_http::chunked::{Decoder, LAST_CHUNK, write_chunk};
use sibuna_http::{Method, Request};

use crate::edit::HeadEdit;
use crate::fields::find_blank_line;
use crate::proxy::{Audit, ProxyError, Upload};
use crate::relay::client_head_error;
use crate::request::write_request_head;
use crate::response::{
    Framing, MAX_RESPONSE_HEAD, chunk_size, is_trailer_line, parse_response_head,
    write_client_head, write_response_fields,
};
use crate::upgrade::{self, Handshake};

/// Informational heads relayed before a final one, as in the blocking relay.
const MAX_INFORMATIONAL: u8 = 8;

/// What [`encode_request`] learned about a request.
#[derive(Clone, Copy, Debug)]
pub struct Outbound {
    /// The WebSocket handshake the request offers, to be passed to [`ResponseRelay::new`].
    pub handshake: Option<Offer>,
    /// The request is idempotent and fully buffered, so it may be sent again on a fresh
    /// socket when a pooled one turns out to be closed. The caller may narrow this by
    /// the size of the body (SID 0019).
    pub retryable: bool,
    /// The origin socket may be pooled after a clean response: the request sent no body.
    pub poolable: bool,
    /// The whole body was buffered, so the client connection holds no byte of it.
    pub buffered: bool,
    /// The request method is `HEAD`.
    pub head_request: bool,
    /// The rest of the body, to be fed from the client.
    pub upload: UploadRelay,
}

/// A validated WebSocket offer: the accept value the origin must answer with.
#[derive(Clone, Copy, Debug)]
pub struct Offer(Handshake);

/// Appends the origin request for an admitted `request` to `out`: the head with the audit
/// fields and the body bytes already buffered in `request.body`.
///
/// # Errors
///
/// [`ProxyError::InvalidUpgrade`] for a malformed upgrade, and
/// [`ProxyError::UpstreamWriteFailed`] for a request path that is not in normal form.
/// `out` may then hold a partial head and must be discarded.
pub fn encode_request(
    out: &mut Vec<u8>,
    request: &Request<'_>,
    upload: Upload,
    audit: &Audit<'_>,
) -> Result<Outbound, ProxyError> {
    let handshake = upgrade::offered(request).map_err(|_| ProxyError::InvalidUpgrade)?;
    let safe = crate::route::is_idempotent(request.method);
    let buffered = upload.is_buffered(request.body.len());
    let failed = |_| ProxyError::UpstreamWriteFailed;
    write_request_head(out, request, &upload, audit, handshake.is_some()).map_err(failed)?;
    let rest = match upload {
        Upload::None => UploadRelay::Done,
        Upload::Length(length) => {
            let held = usize::try_from(length)
                .map_or(request.body.len(), |length| length.min(request.body.len()));
            out.extend_from_slice(request.body.get(..held).unwrap_or_default());
            match length - held as u64 {
                0 => UploadRelay::Done,
                left => UploadRelay::Length(left),
            }
        }
        Upload::Chunked(decoder) => {
            write_chunk(out, request.body).map_err(failed)?;
            UploadRelay::Chunked(decoder)
        }
    };
    Ok(Outbound {
        handshake: handshake.map(Offer),
        retryable: safe && buffered,
        poolable: !upload.carries_body(),
        buffered,
        head_request: request.method == Method::Head,
        upload: rest,
    })
}

/// The rest of a request body on its way to the origin.
#[derive(Clone, Copy, Debug)]
pub enum UploadRelay {
    /// Nothing more follows.
    Done,
    /// This many bytes follow unchanged.
    Length(u64),
    /// The rest of a chunked body follows. It is decoded and each piece is written as one
    /// canonical chunk (SID 0009).
    Chunked(Decoder),
}

impl UploadRelay {
    /// True when the origin has the whole body.
    pub fn is_done(&self) -> bool {
        matches!(self, UploadRelay::Done)
    }

    /// Consumes client bytes from the start of `input` and appends origin bytes to `out`.
    /// Returns the count consumed. A chunked body is decoded in place, so `input` is
    /// mutable; bytes that were not consumed are unchanged and must be passed again with
    /// more bytes behind them.
    ///
    /// # Errors
    ///
    /// [`ProxyError::MalformedRequestBody`] when a chunked body breaks its grammar. The
    /// origin then holds a truncated body, never a complete altered one.
    pub fn feed(&mut self, input: &mut [u8], out: &mut Vec<u8>) -> Result<usize, ProxyError> {
        match self {
            UploadRelay::Done => Ok(0),
            UploadRelay::Length(left) => {
                let count =
                    usize::try_from(*left).map_or(input.len(), |left| left.min(input.len()));
                out.extend_from_slice(input.get(..count).unwrap_or_default());
                *left -= count as u64;
                if *left == 0 {
                    *self = UploadRelay::Done;
                }
                Ok(count)
            }
            UploadRelay::Chunked(decoder) => {
                let step = decoder.decode(input).map_err(|_| ProxyError::MalformedRequestBody)?;
                let data = input.get(..step.output).unwrap_or_default();
                // Writing to a vector cannot fail.
                let _ = write_chunk(out, data);
                if decoder.is_done() {
                    out.extend_from_slice(LAST_CHUNK);
                    *self = UploadRelay::Done;
                }
                Ok(step.consumed)
            }
        }
    }
}

/// What a finished response leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The client connection may serve another request, as far as the response decides.
    /// A caller that cannot tell where a streamed request body ends also requires
    /// [`Outbound::buffered`]. A caller that relays the body through
    /// [`UploadRelay`] requires that the relay is done.
    pub client_keep: bool,
    /// The origin socket is at a clean message boundary and may be pooled, when
    /// [`Outbound::poolable`] allows it too.
    pub origin_reusable: bool,
}

/// The progress of a response after one [`ResponseRelay::feed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fed {
    /// More origin bytes are needed.
    More,
    /// The response is complete.
    Done(Outcome),
    /// The origin accepted the offered upgrade. The 101 head is in the output, and every
    /// further byte in either direction belongs to the tunnel.
    Upgraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Head,
    Length(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailers,
    UntilClose,
    Finished,
}

/// Turns the bytes of one origin response into the bytes the client receives.
#[derive(Debug)]
pub struct ResponseRelay {
    state: State,
    offer: Option<Handshake>,
    head_request: bool,
    client_keep_alive: bool,
    /// Bytes of the current head already searched for the blank line.
    scanned: usize,
    informational: u8,
    received: bool,
    status: u16,
    keep: bool,
    origin_keep: bool,
}

impl ResponseRelay {
    /// A relay for the response to one request. `client_keep_alive` says whether the client
    /// asked to keep its connection.
    pub fn new(outbound: &Outbound, client_keep_alive: bool) -> ResponseRelay {
        ResponseRelay {
            state: State::Head,
            offer: outbound.handshake.map(|offer| offer.0),
            head_request: outbound.head_request,
            client_keep_alive,
            scanned: 0,
            informational: 0,
            received: false,
            status: 0,
            keep: false,
            origin_keep: false,
        }
    }

    /// The final status, or zero before the final head arrived.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// True once the final head is in the output. Before that the caller may still answer
    /// an error of its own.
    pub fn responded(&self) -> bool {
        self.status != 0
    }

    /// Consumes origin bytes from the start of `input` and appends client bytes to `out`.
    /// Returns the count consumed and the progress. Unconsumed bytes must be passed again
    /// with more bytes behind them; the relay never needs more than
    /// [`MAX_RESPONSE_HEAD`] unconsumed bytes. `on_head` receives the final status and the
    /// raw final head once.
    ///
    /// # Errors
    ///
    /// [`ProxyError::UpstreamReadFailed`] for a malformed, oversized or unrequested head,
    /// before anything but informational heads reached `out`.
    /// [`ProxyError::UpstreamTruncated`] for broken body framing after the head.
    pub fn feed(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_head: &mut dyn FnMut(u16, &[u8]),
    ) -> Result<(usize, Fed), ProxyError> {
        self.feed_edited(input, out, on_head, &HeadEdit::default())
    }

    /// As [`ResponseRelay::feed`], and applies `edit` to the final head before it reaches
    /// `out` (SID 0019). Informational heads and the head of an accepted upgrade pass
    /// unedited.
    ///
    /// # Errors
    ///
    /// As [`ResponseRelay::feed`].
    pub fn feed_edited(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_head: &mut dyn FnMut(u16, &[u8]),
        edit: &HeadEdit<'_>,
    ) -> Result<(usize, Fed), ProxyError> {
        self.received |= !input.is_empty();
        let mut used = 0;
        loop {
            let rest = input.get(used..).unwrap_or_default();
            let step = match self.state {
                State::Head => self.head(rest, out, on_head, edit)?,
                State::Length(left) => Self::data(rest, out, left, State::Length, State::Finished),
                State::ChunkData(left) => {
                    Self::data(rest, out, left, State::ChunkData, State::ChunkEnd)
                }
                State::ChunkSize => Self::size_line(rest, out)?,
                State::ChunkEnd => Self::line(rest, out, |line| line == b"\r\n")?
                    .map(|length| (length, State::ChunkSize)),
                State::Trailers => Self::trailer(rest, out)?,
                State::UntilClose => {
                    out.extend_from_slice(rest);
                    return Ok((input.len(), Fed::More));
                }
                State::Finished => None,
            };
            let Some((count, next)) = step else {
                return Ok((used, self.progress(used == input.len())));
            };
            used += count;
            if self.upgraded() {
                return Ok((used, Fed::Upgraded));
            }
            self.state = next;
            if next == State::Finished {
                return Ok((used, self.progress(used == input.len())));
            }
        }
    }

    /// The origin closed its sending side.
    ///
    /// # Errors
    ///
    /// [`ProxyError::UpstreamClosed`] when no byte of a response ever arrived,
    /// [`ProxyError::UpstreamReadFailed`] inside a head, and
    /// [`ProxyError::UpstreamTruncated`] inside a framed body.
    pub fn end_of_stream(&mut self) -> Result<Outcome, ProxyError> {
        match self.state {
            State::UntilClose | State::Finished => {
                self.state = State::Finished;
                Ok(Outcome { client_keep: self.keep, origin_reusable: false })
            }
            State::Head if !self.received => Err(ProxyError::UpstreamClosed),
            State::Head => Err(ProxyError::UpstreamReadFailed),
            _ => Err(ProxyError::UpstreamTruncated),
        }
    }

    fn upgraded(&self) -> bool {
        self.status == 101
    }

    fn progress(&self, drained: bool) -> Fed {
        if self.state != State::Finished {
            return Fed::More;
        }
        // Bytes after the end of a response belong to no request of ours.
        Fed::Done(Outcome { client_keep: self.keep, origin_reusable: self.origin_keep && drained })
    }

    /// Handles one head once it is complete. Returns its length and the next state.
    fn head(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_head: &mut dyn FnMut(u16, &[u8]),
        edit: &HeadEdit<'_>,
    ) -> Result<Option<(usize, State)>, ProxyError> {
        let from = self.scanned.min(input.len());
        let Some(index) = input.get(from..).and_then(find_blank_line) else {
            if input.len() >= MAX_RESPONSE_HEAD {
                return Err(ProxyError::UpstreamReadFailed);
            }
            // A blank line may straddle the next piece: search the last three bytes again.
            self.scanned = input.len().saturating_sub(3);
            return Ok(None);
        };
        let length = from + index + 4;
        if length > MAX_RESPONSE_HEAD {
            return Err(ProxyError::UpstreamReadFailed);
        }
        self.scanned = 0;
        let head = input.get(..length).unwrap_or_default();
        let parsed = parse_response_head(head, false).ok_or(ProxyError::UpstreamReadFailed)?;
        if parsed.status == 101 {
            return self.switch(head, out, on_head).map(|()| Some((length, State::Finished)));
        }
        if parsed.status < 200 {
            if self.informational == MAX_INFORMATIONAL {
                return Err(ProxyError::UpstreamReadFailed);
            }
            self.informational += 1;
            write_client_head(out, head, true).map_err(client_head_error)?;
            return Ok(Some((length, State::Head)));
        }
        let parsed =
            parse_response_head(head, self.head_request).ok_or(ProxyError::UpstreamReadFailed)?;
        on_head(parsed.status, head);
        self.keep = self.client_keep_alive && parsed.framing != Framing::UntilClose;
        let start = out.len();
        write_client_head(out, head, self.keep).map_err(client_head_error)?;
        edit.apply(out, start);
        self.status = parsed.status;
        let framed = matches!(parsed.framing, Framing::Length(_) | Framing::Chunked);
        self.origin_keep = parsed.keep_alive && framed;
        let next = match parsed.framing {
            Framing::None | Framing::Length(0) => State::Finished,
            Framing::Length(length) => State::Length(length),
            Framing::Chunked => State::ChunkSize,
            Framing::UntilClose => State::UntilClose,
        };
        Ok(Some((length, next)))
    }

    /// Relays an accepted 101 with Sibuna's connection fields.
    fn switch(
        &mut self,
        head: &[u8],
        out: &mut Vec<u8>,
        on_head: &mut dyn FnMut(u16, &[u8]),
    ) -> Result<(), ProxyError> {
        let accepted = self.offer.as_ref().is_some_and(|offer| upgrade::accepted(offer, head));
        if !accepted {
            return Err(ProxyError::UpstreamReadFailed);
        }
        write_response_fields(out, head).map_err(client_head_error)?;
        out.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        on_head(101, head);
        self.status = 101;
        Ok(())
    }

    /// Passes up to `left` body bytes through.
    fn data(
        input: &[u8],
        out: &mut Vec<u8>,
        left: u64,
        more: fn(u64) -> State,
        done: State,
    ) -> Option<(usize, State)> {
        let count = usize::try_from(left).map_or(input.len(), |left| left.min(input.len()));
        if count == 0 {
            return None;
        }
        out.extend_from_slice(input.get(..count).unwrap_or_default());
        let left = left - count as u64;
        Some((count, if left == 0 { done } else { more(left) }))
    }

    /// Relays the next line when it is complete and `valid`. Returns its length.
    fn line(
        input: &[u8],
        out: &mut Vec<u8>,
        valid: impl Fn(&[u8]) -> bool,
    ) -> Result<Option<usize>, ProxyError> {
        let Some(index) = input.iter().position(|&byte| byte == b'\n') else {
            // A line longer than a head is a framing error, never an unbounded wait.
            return if input.len() >= MAX_RESPONSE_HEAD {
                Err(ProxyError::UpstreamTruncated)
            } else {
                Ok(None)
            };
        };
        let line = input.get(..=index).unwrap_or_default();
        if !valid(line) {
            return Err(ProxyError::UpstreamTruncated);
        }
        out.extend_from_slice(line);
        Ok(Some(line.len()))
    }

    fn size_line(input: &[u8], out: &mut Vec<u8>) -> Result<Option<(usize, State)>, ProxyError> {
        let Some(length) = Self::line(input, out, |line| chunk_size(line).is_some())? else {
            return Ok(None);
        };
        let size = chunk_size(input.get(..length).unwrap_or_default()).unwrap_or(0);
        Ok(Some((length, if size == 0 { State::Trailers } else { State::ChunkData(size) })))
    }

    fn trailer(input: &[u8], out: &mut Vec<u8>) -> Result<Option<(usize, State)>, ProxyError> {
        let valid = |line: &[u8]| line == b"\r\n" || is_trailer_line(line);
        let Some(length) = Self::line(input, out, valid)? else { return Ok(None) };
        Ok(Some((length, if length == 2 { State::Finished } else { State::Trailers })))
    }
}

#[cfg(test)]
mod tests;
