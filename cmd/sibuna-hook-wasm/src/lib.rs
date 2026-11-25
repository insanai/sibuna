//! An example hook for the Wasm tier of Sibuna (SID 0030), compiled to
//! `wasm32-unknown-unknown`.
//!
//! It shows the whole ABI of version 1 in one file:
//!
//! - at the connection stage it denies the client `127.0.0.2`;
//! - at the request stage it denies a path under `/admin` unless the request carries
//!   `x-role: admin`, asks for a challenge under `/guarded`, and marks every admitted
//!   request with the field `X-Hook: example`;
//! - at the telemetry stage it counts the samples it saw.
//!
//! Build with `cargo build -p sibuna-hook-wasm --target wasm32-unknown-unknown --profile
//! wasm`. The result is committed as `crates/plugin/tests/data/example_hook.wasm`, so the
//! workspace needs no WebAssembly toolchain.
//!
//! The view arrives in a static buffer. Its layout is the wire form of the record: 48
//! fixed bytes, then seven texts and the fields, each text a `u16` length and its bytes.
//!
//! # Threading
//!
//! The host runs one invocation at a time on an instance, and each thread of the host
//! has an instance of its own. On the host (tests only) callers use [`judge`], which
//! touches no static.
#![no_std]
// The exports hand out the address of a static buffer and read what the host wrote
// there; that is the FFI boundary, and the only unsafe code, of this crate.
#![allow(unsafe_code)]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

use core::cell::UnsafeCell;

/// The size of the input buffer that the host writes the view into.
pub const INPUT_LEN: usize = 8192;
/// The verdict codes of the ABI.
pub const ADMIT: i32 = 0;
/// See [`ADMIT`].
pub const DENY: i32 = 1;
/// See [`ADMIT`].
pub const CHALLENGE: i32 = 2;

/// A static that the exports mutate. The host runs one invocation at a time, so at
/// most one reference into a cell is live at any moment.
struct ExportCell<T>(UnsafeCell<T>);

// SAFETY: a WebAssembly instance without shared memory is single-threaded, and the
// host tests do not touch the statics.
unsafe impl<T> Sync for ExportCell<T> {}

static INPUT: ExportCell<[u8; INPUT_LEN]> = ExportCell(UnsafeCell::new([0; INPUT_LEN]));
static SAMPLES: ExportCell<u32> = ExportCell(UnsafeCell::new(0));

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "sibuna")]
unsafe extern "C" {
    fn add_header(line: *const u8, length: usize) -> i32;
}

/// A cursor over the wire form of a view.
struct Texts<'a> {
    rest: &'a [u8],
}

impl<'a> Texts<'a> {
    /// The next text, or an empty one at the end of the view.
    fn next(&mut self) -> &'a [u8] {
        let Some((length, rest)) = self.rest.split_first_chunk::<2>() else { return b"" };
        let length = usize::from(u16::from_le_bytes(*length));
        let Some((text, rest)) = rest.split_at_checked(length) else { return b"" };
        self.rest = rest;
        text
    }
}

/// Judges the encoded view `view` at `stage` (1 connection, 2 request). Returns the
/// verdict code and whether the request should be marked.
pub fn judge(view: &[u8]) -> (i32, bool) {
    let Some((fixed, texts)) = view.split_first_chunk::<48>() else { return (DENY, false) };
    let stage = fixed[1];
    if stage == 1 {
        let blocked = fixed[8..12] == [127, 0, 0, 2] && fixed[3] & 0b10 == 0;
        return (if blocked { DENY } else { ADMIT }, false);
    }
    let count = u16::from_le_bytes([fixed[42], fixed[43]]);
    let mut texts = Texts { rest: texts };
    // frontend, server name, JA4, method and host come before the path.
    for _ in 0..5 {
        texts.next();
    }
    let path = texts.next();
    texts.next();
    if path.starts_with(b"/guarded") {
        return (CHALLENGE, false);
    }
    if !path.starts_with(b"/admin") {
        return (ADMIT, true);
    }
    for _ in 0..count {
        let (name, value) = (texts.next(), texts.next());
        if name.eq_ignore_ascii_case(b"x-role") && value == b"admin" {
            return (ADMIT, true);
        }
    }
    (DENY, false)
}

/// The version of the ABI this module speaks.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_abi() -> i32 {
    1
}

/// The address of the input buffer in linear memory.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_input() -> *mut u8 {
    INPUT.0.get().cast()
}

/// The size of the input buffer.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_input_size() -> usize {
    INPUT_LEN
}

/// The view that the host wrote, `length` bytes of the input buffer.
fn input(length: usize) -> &'static [u8] {
    // SAFETY: the host wrote the view before this call and writes nothing during it,
    // and no other reference into the buffer is live.
    let buffer: &'static [u8; INPUT_LEN] = unsafe { &*INPUT.0.get() };
    buffer.get(..length).unwrap_or_default()
}

/// Judges a new connection or UDP mapping.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_on_connection(length: usize) -> i32 {
    judge(input(length)).0
}

/// Judges an admitted request, and marks it when it passes.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_on_request(length: usize) -> i32 {
    let (verdict, mark) = judge(input(length));
    if mark {
        mark_request();
    }
    verdict
}

/// Adds the field `X-Hook: example` to the request for the server.
fn mark_request() {
    #[cfg(target_arch = "wasm32")]
    {
        let line = b"X-Hook: example";
        // SAFETY: `line` is a live slice, and the host only reads it during the call.
        unsafe { add_header(line.as_ptr(), line.len()) };
    }
}

/// Counts an ended request. The state lives in the instance of one host thread.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_on_telemetry(_length: usize) -> i32 {
    // SAFETY: one invocation runs at a time, so no other reference is live.
    let samples = unsafe { &mut *SAMPLES.0.get() };
    *samples = samples.wrapping_add(1);
    *samples as i32
}

/// Traps on a panic. Nothing here panics; trapping keeps the module free of
/// formatting code and imports.
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// The wire form of a view at `stage` from `client` with `path` and one field.
    fn view(stage: u8, client: [u8; 4], path: &[u8], field: Option<(&[u8], &[u8])>) -> Vec<u8> {
        let mut out = std::vec![0u8; 48];
        (out[0], out[1], out[2]) = (1, stage, 3);
        out[8..12].copy_from_slice(&client);
        out[42] = u8::from(field.is_some());
        let mut text = |bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(bytes);
        };
        for bytes in [&b"web"[..], b"", b"", b"GET", b"example.test", path, b""] {
            text(bytes);
        }
        if let Some((name, value)) = field {
            text(name);
            text(value);
        }
        out
    }

    #[test]
    fn the_connection_stage_denies_the_blocked_client() {
        assert_eq!(judge(&view(1, [127, 0, 0, 2], b"", None)).0, DENY);
        assert_eq!(judge(&view(1, [127, 0, 0, 1], b"", None)).0, ADMIT);
    }

    #[test]
    fn the_request_stage_guards_the_admin_paths() {
        assert_eq!(judge(&view(2, [127, 0, 0, 1], b"/", None)), (ADMIT, true));
        assert_eq!(judge(&view(2, [127, 0, 0, 1], b"/admin/users", None)), (DENY, false));
        let role = Some((&b"X-Role"[..], &b"admin"[..]));
        assert_eq!(judge(&view(2, [127, 0, 0, 1], b"/admin/users", role)), (ADMIT, true));
        let other = Some((&b"X-Role"[..], &b"guest"[..]));
        assert_eq!(judge(&view(2, [127, 0, 0, 1], b"/admin", other)), (DENY, false));
        assert_eq!(judge(&view(2, [127, 0, 0, 1], b"/guarded", None)), (CHALLENGE, false));
    }

    #[test]
    fn a_view_that_is_cut_short_is_denied() {
        assert_eq!(judge(&[0; 10]), (DENY, false));
    }
}
