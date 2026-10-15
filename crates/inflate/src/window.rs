//! The sliding window: decoded bytes that matches may still refer to, followed by bytes not
//! yet handed to the caller, followed by free room.
//!
//! ```text
//!   0          delivered          pos                    len
//!   | history  |  pending output  |  room for new output  |
//! ```
//!
//! DEFLATE matches reach back at most 32 KiB. When the room runs low, we move the last
//! 32 KiB of history (and any pending bytes) to the front. The buffer is four times the
//! history, so the move copies at most a third of what was decoded since the last one.

/// How far back a DEFLATE match may reach.
pub(crate) const HISTORY: usize = 32 * 1024;
/// The size of the window buffer.
const WINDOW_LEN: usize = 4 * HISTORY;
/// The room below which `make_room` slides the window.
const MIN_ROOM: usize = HISTORY;

/// The decoded bytes of the stream, as described in the module comment.
pub(crate) struct Window {
    /// The bytes.
    pub(crate) buf: Box<[u8]>,
    /// Where the next decoded byte goes.
    pub(crate) pos: usize,
    /// The first byte not yet handed to the caller.
    delivered: usize,
    /// Where the output of the current gzip member (or raw stream) starts; matches may not
    /// reach before it. After a slide it is clamped to zero, which is safe because the
    /// window then holds at least `HISTORY` bytes before `pos`.
    pub(crate) member_start: usize,
}

impl Window {
    /// Allocates an empty window.
    pub(crate) fn new() -> Self {
        Self { buf: vec![0; WINDOW_LEN].into_boxed_slice(), pos: 0, delivered: 0, member_start: 0 }
    }

    /// Forgets all bytes, delivered or not.
    pub(crate) fn clear(&mut self) {
        self.pos = 0;
        self.delivered = 0;
        self.member_start = 0;
    }

    /// Starts a new gzip member: its matches may not reach into earlier members.
    pub(crate) fn start_member(&mut self) {
        self.member_start = self.pos;
    }

    /// Returns the decoded bytes not yet handed to the caller.
    pub(crate) fn pending(&self) -> &[u8] {
        &self.buf[self.delivered..self.pos]
    }

    /// Records that the caller took the first `count` pending bytes.
    pub(crate) fn mark_delivered(&mut self, count: usize) {
        debug_assert!(count <= self.pos - self.delivered);
        self.delivered += count;
    }

    /// Slides the window when the room is low, keeping `HISTORY` bytes of history and all
    /// pending bytes.
    pub(crate) fn make_room(&mut self) {
        if self.buf.len() - self.pos >= MIN_ROOM {
            return;
        }
        let keep_from = self.pos.saturating_sub(HISTORY).min(self.delivered);
        if keep_from == 0 {
            return;
        }
        self.buf.copy_within(keep_from..self.pos, 0);
        self.pos -= keep_from;
        self.delivered -= keep_from;
        self.member_start = self.member_start.saturating_sub(keep_from);
    }
}

/// Appends a copy of the `length` bytes that start `distance` bytes before `pos`, as
/// DEFLATE defines it: byte by byte, so a distance shorter than the length repeats the
/// pattern.
///
/// The caller guarantees `1 <= distance <= pos` and `pos + length <= buf.len()`, which
/// keeps every index below in bounds; the 16-byte path also checks `pos + 16 <= buf.len()`.
#[inline(always)]
pub(crate) fn copy_match(buf: &mut [u8], pos: usize, distance: usize, length: usize) {
    let source = pos - distance;
    if distance >= length {
        // No overlap: one plain copy. A short match is copied as a fixed 16 bytes when the
        // free room after `pos` allows it, which avoids a call into memmove for typical
        // matches; the bytes written past the match are free room and get overwritten.
        if length <= 16 && pos + 16 <= buf.len() && distance >= 16 {
            let mut chunk = [0u8; 16];
            chunk.copy_from_slice(&buf[source..source + 16]);
            buf[pos..pos + 16].copy_from_slice(&chunk);
        } else {
            buf.copy_within(source..source + length, pos);
        }
    } else if distance == 1 {
        let byte = buf[source];
        buf[pos..pos + length].fill(byte);
    } else {
        // The bytes from `source` to `pos + done` repeat with period `distance`, and `done`
        // stays a multiple of it, so each round can copy everything written so far.
        let mut done = 0;
        while done < length {
            let count = (length - done).min(distance + done);
            buf.copy_within(source..source + count, pos + done);
            done += count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_copy(buf: &mut [u8], pos: usize, distance: usize, length: usize) {
        for i in 0..length {
            buf[pos + i] = buf[pos - distance + i];
        }
    }

    #[test]
    fn copy_match_matches_bytewise_definition() {
        for distance in 1..40 {
            for length in 3..80 {
                let mut fast: Vec<u8> = (0..200u8).collect();
                let mut slow = fast.clone();
                copy_match(&mut fast, 50, distance.min(50), length);
                reference_copy(&mut slow, 50, distance.min(50), length);
                assert_eq!(&fast[..50 + length], &slow[..50 + length], "{distance} {length}");
            }
        }
    }

    #[test]
    fn slide_keeps_history_and_pending_bytes() {
        let mut window = Window::new();
        let len = window.buf.len();
        for (i, byte) in window.buf.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        window.pos = len - 10;
        window.mark_delivered(len - 20_000);
        window.member_start = 5;
        window.make_room();
        // Pending bytes start 20,000 before the end; history needs only 32 KiB, so the
        // window keeps from 32 KiB before the old position.
        let keep_from = len - 10 - HISTORY;
        assert_eq!(window.pos, HISTORY);
        assert_eq!(window.pending().len(), 20_000 - 10);
        assert_eq!(window.member_start, 0);
        assert_eq!(window.buf[0], (keep_from % 251) as u8);
    }
}
