//! Body relays in both directions of an exchange.
//!
//! Every relay is built on one copy step ([`step`]): forward whatever the source already
//! holds; only when it holds nothing, flush the destination and then read once. A stream of
//! small writes is therefore delivered as it is produced, and a bulk transfer still moves a
//! full buffer per read and write.
//!
//! Deadlines are activity-based. Origin bytes refresh the activity stamp on every read, so the
//! idle deadline measures the origin's silence and never the length of a response. Upload
//! bytes come from the untrusted side and refresh it only per [`UPLOAD_CREDIT`] bytes, which
//! asks a client for at least 16 KiB per idle period: the slow-body defence of minimum-rate
//! request timeouts.

use std::io::{Read, Write};

use sibuna_http::chunked::{Decoder, LAST_CHUNK, write_chunk};

use crate::buffered::{ReadError, Reader};
use crate::fields::find_blank_line;
use crate::idle::Activity;
use crate::proxy::{Audit, ProxyError};
use crate::response::{
    Framing, MAX_RESPONSE_HEAD, chunk_size, parse_response_head, write_client_head,
};

/// Upload bytes per activity refresh.
pub(crate) const UPLOAD_CREDIT: usize = 16 * 1024;

/// The liveness of the exchange in flight; without an activity nothing is recorded.
#[derive(Clone, Copy)]
pub(crate) struct Progress<'a> {
    pub(crate) activity: Option<&'a Activity>,
}

impl Progress<'_> {
    #[inline]
    pub(crate) fn touch(self) {
        if let Some(activity) = self.activity {
            activity.touch();
        }
    }
}

/// Why one copy step stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    ReadFailed,
    WriteFailed,
    EndOfStream,
}

/// Forwards up to `limit` bytes the source already holds. When it holds none, flushes the
/// sink first, so bytes already relayed reach the peer before this side waits, and then reads
/// once. Returns the number of bytes forwarded, at least one.
pub(crate) fn step<R: Read, W: Write + ?Sized>(
    source: &mut Reader<'_, R>,
    sink: &mut W,
    limit: u64,
) -> Result<usize, Moved> {
    if source.buffered_len() == 0 {
        sink.flush().map_err(|_| Moved::WriteFailed)?;
        match source.fill_more() {
            Ok(_) => {}
            Err(ReadError::EndOfStream) => return Err(Moved::EndOfStream),
            Err(_) => return Err(Moved::ReadFailed),
        }
    }
    let bytes = source.buffered();
    let count = usize::try_from(limit).map_or(bytes.len(), |limit| limit.min(bytes.len()));
    sink.write_all(bytes.get(..count).unwrap_or_default()).map_err(|_| Moved::WriteFailed)?;
    source.consume(count);
    Ok(count)
}

/// Copies exactly `count` origin bytes to the client. Once the head has been sent, a failure
/// aborts the exchange; it never produces a second response.
pub(crate) fn copy_exact<R: Read, W: Write + ?Sized>(
    origin: &mut Reader<'_, R>,
    client: &mut W,
    count: u64,
    progress: Progress<'_>,
) -> Result<(), ProxyError> {
    let mut left = count;
    while left > 0 {
        let moved = step(origin, client, left).map_err(|moved| match moved {
            Moved::WriteFailed => ProxyError::ClientFailed,
            Moved::ReadFailed | Moved::EndOfStream => ProxyError::UpstreamTruncated,
        })?;
        progress.touch();
        left -= moved as u64;
    }
    Ok(())
}

/// Copies a close-delimited body until the origin closes.
pub(crate) fn copy_remaining<R: Read, W: Write + ?Sized>(
    origin: &mut Reader<'_, R>,
    client: &mut W,
    progress: Progress<'_>,
) -> Result<(), ProxyError> {
    loop {
        match step(origin, client, u64::MAX) {
            Ok(_) => progress.touch(),
            Err(Moved::EndOfStream) => return Ok(()),
            Err(Moved::WriteFailed) => return Err(ProxyError::ClientFailed),
            Err(Moved::ReadFailed) => return Err(ProxyError::UpstreamTruncated),
        }
    }
}

/// The length of the next origin line (through its LF) once it is buffered, read with the
/// same flush-before-wait discipline. A line longer than the read buffer is a framing error,
/// never an unbounded wait.
fn buffer_line<R: Read, W: Write + ?Sized>(
    origin: &mut Reader<'_, R>,
    client: &mut W,
    progress: Progress<'_>,
) -> Result<usize, ProxyError> {
    loop {
        let bytes = origin.buffered();
        if let Some(index) = bytes.iter().position(|&byte| byte == b'\n') {
            return Ok(index + 1);
        }
        if bytes.len() == origin.capacity() {
            return Err(ProxyError::UpstreamTruncated);
        }
        client.flush().map_err(|_| ProxyError::ClientFailed)?;
        origin.fill_more().map_err(|_| ProxyError::UpstreamTruncated)?;
        progress.touch();
    }
}

/// Copies a chunked body verbatim: size lines, chunk data with its CRLF, the last chunk and
/// any trailer section.
pub(crate) fn relay_chunked<R: Read, W: Write + ?Sized>(
    origin: &mut Reader<'_, R>,
    client: &mut W,
    progress: Progress<'_>,
) -> Result<(), ProxyError> {
    loop {
        let length = buffer_line(origin, client, progress)?;
        let line = origin.buffered().get(..length).unwrap_or_default();
        let size = chunk_size(line).ok_or(ProxyError::UpstreamTruncated)?;
        client.write_all(line).map_err(|_| ProxyError::ClientFailed)?;
        origin.consume(length);
        if size == 0 {
            break;
        }
        // Zig computed `size + 2` unchecked; a size near 2^64 is never delivered anyway.
        copy_exact(origin, client, size.saturating_add(2), progress)?;
    }
    loop {
        let length = buffer_line(origin, client, progress)?;
        let line = origin.buffered().get(..length).unwrap_or_default();
        let last = line == b"\r\n" || line == b"\n";
        client.write_all(line).map_err(|_| ProxyError::ClientFailed)?;
        origin.consume(length);
        if last {
            return Ok(());
        }
    }
}

/// Relays `rest` further body bytes from the client to the origin: first from `pending`
/// (bytes the daemon already read), then from the client source.
pub(crate) fn relay_body<R: Read, W: Write + ?Sized>(
    pending: &[u8],
    client: &mut Reader<'_, R>,
    origin: &mut W,
    rest: u64,
    progress: Progress<'_>,
) -> Result<(), ProxyError> {
    let mut left = rest;
    let mut credit = 0;
    let first = usize::try_from(left).map_or(pending.len(), |left| left.min(pending.len()));
    if first > 0 {
        let bytes = pending.get(..first).unwrap_or_default();
        origin.write_all(bytes).map_err(|_| ProxyError::UpstreamWriteFailed)?;
        left -= first as u64;
        credit += first;
        if credit >= UPLOAD_CREDIT || left == 0 {
            progress.touch();
            credit = 0;
        }
    }
    while left > 0 {
        let moved = step(client, origin, left).map_err(|moved| match moved {
            Moved::WriteFailed => ProxyError::UpstreamWriteFailed,
            Moved::ReadFailed | Moved::EndOfStream => ProxyError::ClientFailed,
        })?;
        left -= moved as u64;
        credit += moved;
        if credit >= UPLOAD_CREDIT || left == 0 {
            progress.touch();
            credit = 0;
        }
    }
    Ok(())
}

/// Sends the rest of a chunked request body. Each read is decoded in place and forwarded as
/// one canonical chunk, so chunk boundaries at the origin follow arrival, never the client's
/// choice (SID 0009). The last chunk is written only when the body ends; a framing error
/// leaves the origin with a truncated body.
pub(crate) fn relay_chunked_body<R: Read, W: Write + ?Sized>(
    client: &mut Reader<'_, R>,
    origin: &mut W,
    decoder: &mut Decoder,
    progress: Progress<'_>,
) -> Result<(), ProxyError> {
    let mut credit = 0;
    loop {
        let raw = client.buffered_mut();
        let decoded = decoder.decode(raw).map_err(|_| ProxyError::MalformedRequestBody)?;
        let data = raw.get(..decoded.output).unwrap_or_default();
        write_chunk(origin, data).map_err(|_| ProxyError::UpstreamWriteFailed)?;
        client.consume(decoded.consumed);
        credit += decoded.consumed;
        if credit >= UPLOAD_CREDIT {
            progress.touch();
            credit = 0;
        }
        if decoder.is_done() {
            break;
        }
        origin.flush().map_err(|_| ProxyError::UpstreamWriteFailed)?;
        client.fill_more().map_err(|_| ProxyError::ClientFailed)?;
    }
    origin.write_all(LAST_CHUNK).map_err(|_| ProxyError::UpstreamWriteFailed)?;
    progress.touch();
    Ok(())
}

/// What a relayed exchange leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Relayed {
    /// The client connection may serve another request.
    pub(crate) client_keep: bool,
    /// The origin socket may be pooled for another request.
    pub(crate) origin_reusable: bool,
}

/// Buffers origin bytes until the blank line; returns the head length. The search resumes
/// where the previous one stopped, so a head trickled byte by byte costs linear work.
pub(crate) fn read_response_head<R: Read>(
    origin: &mut Reader<'_, R>,
    progress: Progress<'_>,
) -> Result<usize, ProxyError> {
    let mut scanned = 0;
    loop {
        let bytes = origin.buffered();
        let from = scanned.min(bytes.len());
        if let Some(index) = bytes.get(from..).and_then(find_blank_line) {
            return Ok(from + index + 4);
        }
        if bytes.len() >= MAX_RESPONSE_HEAD {
            return Err(ProxyError::UpstreamReadFailed);
        }
        // A blank line may straddle the next read: rescan the last three bytes.
        scanned = bytes.len().saturating_sub(3);
        let length = bytes.len();
        match origin.fill(length + 1) {
            Ok(()) => progress.touch(),
            Err(ReadError::EndOfStream) if length == 0 => return Err(ProxyError::UpstreamClosed),
            Err(_) => return Err(ProxyError::UpstreamReadFailed),
        }
    }
}

/// Reads heads until a final one (or a 101) and returns its length. Informational heads
/// before it are relayed to the client at once; they are bounded in number (eight) as well
/// as in size, including unsolicited 100 and 103.
pub(crate) fn final_response_head<R: Read, W: Write + ?Sized>(
    origin: &mut Reader<'_, R>,
    client: &mut W,
    progress: Progress<'_>,
) -> Result<usize, ProxyError> {
    for index in 0..9 {
        let length = read_response_head(origin, progress)?;
        let head = origin.buffered().get(..length).unwrap_or_default();
        let parsed = parse_response_head(head, false).ok_or(ProxyError::UpstreamReadFailed)?;
        if parsed.status == 101 || parsed.status >= 200 {
            return Ok(length);
        }
        if index == 8 {
            break;
        }
        write_client_head(client, head, true).map_err(client_head_error)?;
        origin.consume(length);
        client.flush().map_err(|_| ProxyError::ClientFailed)?;
    }
    Err(ProxyError::UpstreamReadFailed)
}

/// Maps a failure to re-emit an origin head: a malformed line is the origin's fault.
pub(crate) fn client_head_error(error: std::io::Error) -> ProxyError {
    if error.kind() == std::io::ErrorKind::InvalidData {
        ProxyError::UpstreamReadFailed
    } else {
        ProxyError::ClientFailed
    }
}

/// Streams the origin response to the client: the head with Sibuna's connection semantics,
/// then the body by its framing. The origin status and the raw head go to the audit sinks
/// before the head is relayed.
pub(crate) fn relay_response<R: Read, W: Write + ?Sized>(
    origin: &mut Reader<'_, R>,
    client: &mut W,
    head_request: bool,
    client_keep_alive: bool,
    audit: &mut Audit<'_>,
    progress: Progress<'_>,
) -> Result<Relayed, ProxyError> {
    let head_length = final_response_head(origin, client, progress)?;
    let head = origin.buffered().get(..head_length).unwrap_or_default();
    let parsed = parse_response_head(head, head_request).ok_or(ProxyError::UpstreamReadFailed)?;
    if parsed.status == 101 {
        return Err(ProxyError::UpstreamReadFailed);
    }
    audit.report(parsed.status, head);
    let keep = client_keep_alive && parsed.framing != Framing::UntilClose;
    write_client_head(client, head, keep).map_err(client_head_error)?;
    origin.consume(head_length);
    match parsed.framing {
        Framing::None => {}
        Framing::Length(length) => copy_exact(origin, client, length, progress)?,
        Framing::Chunked => relay_chunked(origin, client, progress)?,
        Framing::UntilClose => copy_remaining(origin, client, progress)?,
    }
    client.flush().map_err(|_| ProxyError::ClientFailed)?;
    Ok(Relayed { client_keep: keep, origin_reusable: parsed.keep_alive })
}

#[cfg(test)]
mod tests;
