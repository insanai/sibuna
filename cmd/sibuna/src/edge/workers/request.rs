//! Reading one request and deciding it, without waiting (SID 0016).
//!
//! This is the connection loop of `crate::connection` turned inside out. That loop reads
//! until it has what it needs. Here the worker calls [`advance`] whenever bytes arrived,
//! and the function says whether the request is still incomplete. The checks, their order
//! and the dispatch are the same.

use sibuna_http::chunked::Decoder;
use sibuna_http::response::{self, Status};
use sibuna_http::{Method, parse_request};
use sibuna_net::{Activity, Upload, Workspace};

use super::conn::{Buffer, Conn, Linger, Reading};
use crate::client_writer::ClientWriter;
use crate::connection::{
    self, BodyFault, Link, MAX_HEAD_BYTES, MAX_REQUESTS_PER_CONNECTION, UNKNOWN_LENGTH,
};
use crate::dispatch::{Defer, Plan};
use crate::server::Server;
use crate::slot::EngineCache;

/// What a worker lends to every decision it runs.
pub(super) struct Scratch {
    pub workspace: Workspace,
    pub cache: EngineCache,
    pub defer: Defer,
    pub activity: Activity,
    /// The normal forms of the request path and of a forwarded path.
    pub paths: Box<[u8]>,
    /// What the access log learns of the request being decided (SID 0020).
    pub trace: crate::access::Trace,
}

impl Scratch {
    pub fn new() -> Self {
        Self {
            workspace: Workspace::new(),
            cache: EngineCache::new(),
            defer: Defer::default(),
            activity: Activity::new(),
            paths: vec![0; MAX_HEAD_BYTES].into_boxed_slice(),
            trace: crate::access::Trace::default(),
        }
    }
}

/// The state of the request at the start of the input.
pub(super) enum Step {
    /// More bytes are needed. A response to `Expect` may have been written.
    Wait,
    /// A response is in the output. `used` input bytes belonged to the request.
    Answered { keep: bool, used: usize },
    /// The request was admitted. `used` input bytes were encoded into the plan's wire.
    Admitted { plan: Plan, used: usize },
}

/// The body bytes a request brings before it is dispatched.
struct Framed {
    body_len: usize,
    declared: usize,
    upload: Upload,
}

/// Reads as much of the next request as the input holds and dispatches it when it is
/// complete. The caller guarantees that the connection has an input buffer.
pub(super) fn advance(server: &Server, conn: &mut Conn, scratch: &mut Scratch) -> Step {
    let Conn { stream, ingress, peer, admission, input, output, reading, served, linger, .. } =
        conn;
    let Some(buffer) = input.as_mut() else { return Step::Wait };
    let mut link = Link {
        server,
        ingress: Some(*ingress),
        stream: Some(stream),
        writer: ClientWriter::new(&mut *output),
        workspace: &mut scratch.workspace,
        cache: &mut scratch.cache,
        defer: Some(&mut scratch.defer),
        activity: &scratch.activity,
        last: *served + 1 >= MAX_REQUESTS_PER_CONNECTION,
        admission: admission.take(),
        trace: &mut scratch.trace,
    };
    let step = decide(&mut link, buffer, reading, peer.as_bytes(), &mut scratch.paths);
    let tally = link.writer.tally();
    *admission = link.admission.take();
    match step {
        Step::Answered { keep, used } => match scratch.defer.plan.take() {
            // The entry of an admitted request stays in the scratch for the worker.
            Some(plan) => Step::Admitted { plan, used },
            None => {
                let (trace, ingress) = (&mut scratch.trace, Some(*ingress));
                crate::access::settle_written(server, trace, tally, ingress, peer.as_bytes());
                if crate::traffic::refused_body(tally.status) && !keep {
                    *linger = Linger::Wanted;
                }
                if !keep {
                    // The client may reconnect as soon as it reads this answer.
                    *admission = None;
                }
                Step::Answered { keep, used }
            }
        },
        other => other,
    }
}

type Writer<'o> = ClientWriter<&'o mut Vec<u8>>;

fn decide(
    link: &mut Link<'_, Writer<'_>>,
    buffer: &mut Buffer,
    reading: &mut Reading,
    peer: &[u8],
    paths: &mut [u8],
) -> Step {
    link.writer.begin_response(false);
    let closed = Step::Answered { keep: false, used: buffer.len };
    if reading.head_len == 0 {
        match find_head(buffer.filled(), reading) {
            Ok(Some(length)) => reading.head_len = length,
            Ok(None) => return Step::Wait,
            Err(()) => {
                let text = b"Request head exceeds 16 KB";
                let _ =
                    response::write_text(&mut link.writer, Status::HeadersTooLarge, text, false);
                return closed;
            }
        }
    }
    let head_len = reading.head_len;
    let (head, rest) = buffer.filled().split_at(head_len);
    let request = match parse_request(head) {
        Ok(request) => request,
        Err(error) => {
            connection::reject_head(link, error);
            return closed;
        }
    };
    // Every response to HEAD, Sibuna's own included, is a head without a body.
    link.writer.begin_response(request.method == Method::Head);
    link.writer.set_own(crate::traffic::own_policy(link.server, link.ingress, &request));
    if connection::has_repeated_host(&request) {
        connection::reject_repeated_host(link);
        return closed;
    }
    let declared = request.content_length().unwrap_or(0);
    if !reading.continued {
        if !connection::expect_continue(link, &request, declared, peer) {
            return closed;
        }
        reading.continued = true;
    }
    let chunked = request.chunked;
    if declared == 0 && !chunked {
        let upload = Upload::declared(&request);
        let keep = connection::dispatch(link, request, rest, upload, 0, peer, paths);
        return Step::Answered { keep, used: head_len };
    }
    match frame_body(buffer, reading, declared, chunked) {
        Ok(Some(framed)) => dispatch_body(link, buffer, head_len, &framed, peer, paths),
        Ok(None) => Step::Wait,
        Err(fault) => {
            let declared = if chunked { UNKNOWN_LENGTH } else { declared };
            let head = buffer.data.get(..head_len).unwrap_or_default();
            connection::reject_body(head, link, peer, declared, fault);
            Step::Answered { keep: false, used: buffer.len }
        }
    }
}

/// Answers a request whose body ended early: the client closed inside it.
pub(super) fn truncated(server: &Server, conn: &mut Conn, scratch: &mut Scratch) {
    let Conn { stream, ingress, peer, admission, input, output, reading, .. } = conn;
    let Some(buffer) = input.as_ref() else { return };
    if reading.head_len == 0 {
        return;
    }
    let mut link = Link {
        server,
        ingress: Some(*ingress),
        stream: Some(stream),
        writer: ClientWriter::new(&mut *output),
        workspace: &mut scratch.workspace,
        cache: &mut scratch.cache,
        defer: None,
        activity: &scratch.activity,
        last: true,
        admission: admission.take(),
        trace: &mut scratch.trace,
    };
    let head = buffer.data.get(..reading.head_len).unwrap_or_default();
    let declared = if reading.decoder.is_some() { UNKNOWN_LENGTH } else { 0 };
    connection::reject_body(head, &mut link, peer.as_bytes(), declared, BodyFault::Truncated);
    let tally = link.writer.tally();
    *admission = link.admission.take();
    let (trace, ingress) = (&mut scratch.trace, Some(*ingress));
    crate::access::settle_written(server, trace, tally, ingress, peer.as_bytes());
}

/// The length of the head once its blank line arrived. An error is a head over the limit.
fn find_head(bytes: &[u8], reading: &mut Reading) -> Result<Option<usize>, ()> {
    let from = reading.searched.saturating_sub(3);
    if let Some(at) = connection::find_blank_line(bytes.get(from..).unwrap_or_default()) {
        let length = from + at + 4;
        return if length > MAX_HEAD_BYTES { Err(()) } else { Ok(Some(length)) };
    }
    if bytes.len() >= MAX_HEAD_BYTES {
        return Err(());
    }
    reading.searched = bytes.len();
    Ok(None)
}

/// Buffers a body as the blocking loop does: a length up to the end of the buffer, or a
/// chunked body decoded in place until it ends or the buffer is full (SID 0009).
fn frame_body(
    buffer: &mut Buffer,
    reading: &mut Reading,
    declared: usize,
    chunked: bool,
) -> Result<Option<Framed>, BodyFault> {
    let head_len = reading.head_len;
    if !chunked {
        let fits = declared.min(buffer.data.len() - head_len);
        if buffer.len < head_len + fits {
            return Ok(None);
        }
        return Ok(Some(Framed {
            body_len: fits,
            declared,
            upload: Upload::Length(declared as u64),
        }));
    }
    let decoder = reading.decoder.get_or_insert_with(Decoder::new);
    let start = head_len + reading.decoded;
    let window = buffer.data.get_mut(start..buffer.len).unwrap_or_default();
    let step = decoder.decode(window).map_err(|_| BodyFault::Malformed)?;
    buffer.remove(start + step.output, start + step.consumed);
    reading.decoded += step.output;
    let decoded = reading.decoded;
    if decoder.is_done() {
        let upload = Upload::Length(decoded as u64);
        return Ok(Some(Framed { body_len: decoded, declared: decoded, upload }));
    }
    if buffer.len == buffer.data.len() {
        let upload = Upload::Chunked(*decoder);
        return Ok(Some(Framed { body_len: decoded, declared: UNKNOWN_LENGTH, upload }));
    }
    Ok(None)
}

fn dispatch_body(
    link: &mut Link<'_, Writer<'_>>,
    buffer: &Buffer,
    head_len: usize,
    framed: &Framed,
    peer: &[u8],
    paths: &mut [u8],
) -> Step {
    let bytes = buffer.filled();
    let end = head_len + framed.body_len;
    // The head was parsed before the body moved the buffer; parsing is deterministic.
    let Ok(mut request) = parse_request(bytes.get(..head_len).unwrap_or_default()) else {
        return Step::Answered { keep: false, used: buffer.len };
    };
    request.body = bytes.get(head_len..end).unwrap_or_default();
    let pending = bytes.get(end..).unwrap_or_default();
    let keep =
        connection::dispatch(link, request, pending, framed.upload, framed.declared, peer, paths);
    Step::Answered { keep, used: end }
}
