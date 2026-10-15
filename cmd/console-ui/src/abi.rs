//! The WebAssembly exports `glue.js` calls, and the allocator of the module.
//!
//! This is the only module with `unsafe` code, for two reasons: the exports must reach one
//! application value from plain `extern "C"` functions, and the allocator must implement
//! the `unsafe` trait `GlobalAlloc`.
//!
//! Single-threaded assumption: the module is built for `wasm32-unknown-unknown` without
//! the `atomics` feature, so it has one thread, and the bridge calls one export at a time
//! (exports never call back into JavaScript). The application value is therefore never
//! reached by two calls at once, and the exclusive reference each export takes cannot
//! alias another. The module is compiled only for `wasm32`, so native tests, which run in
//! parallel threads, never touch the global.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;

use crate::app::{App, INPUT_LIMIT};
use crate::geometry;

/// The allocator: the system allocator, but every block is zeroed before it is freed, so
/// dropped credentials, request bodies and parsed replies leave no copy in linear memory.
/// It replaces Zig's `secureZero` on the fixed event arena.
struct WipeOnFree;

// SAFETY: every method forwards to `System` with the caller's arguments, which satisfy
// `System`'s contracts because they satisfy ours; `dealloc` first writes zeros over the
// block, which the caller still owns and which is `layout.size()` bytes long.
unsafe impl GlobalAlloc for WipeOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; see the impl comment.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; see the impl comment.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: `block` was returned by `alloc` for `layout` and is still owned by the
        // caller, so its `layout.size()` bytes are writable.
        unsafe { std::ptr::write_bytes(block, 0, layout.size()) };
        // The optimiser must assume the zeros are read, so the stores stay.
        std::hint::black_box(block);
        // SAFETY: forwarded unchanged; see the impl comment.
        unsafe { System.dealloc(block, layout) }
    }
    // `realloc` keeps the trait's default: allocate, copy, then `dealloc` the old block,
    // which erases it. Growing in place would never erase the bytes it moved.
}

#[global_allocator]
static ALLOCATOR: WipeOnFree = WipeOnFree;

/// The one application value.
struct Global(UnsafeCell<Option<App>>);

// SAFETY: the module is single-threaded (see the module documentation), so the cell is
// never shared between threads.
unsafe impl Sync for Global {}

static APP: Global = Global(UnsafeCell::new(None));

/// Returns the application, creating it (not started) on first use. `glue.js` calls
/// `sb_init` first, so the exports that return buffer addresses never allocate: the bridge
/// reads `memory.buffer` before it calls them, and growing memory would detach it.
fn app() -> &'static mut App {
    // SAFETY: single-threaded and not reentrant (see the module documentation): no other
    // reference to the cell's value is alive while an export runs, and each export takes
    // this reference once and drops it before returning.
    let slot = unsafe { &mut *APP.0.get() };
    slot.get_or_insert_with(App::new)
}

/// Starts the interface: a fresh state at the loading phase and a session check.
#[unsafe(no_mangle)]
pub extern "C" fn sb_init() {
    app().start();
}

/// Handles the event of kind `kind` whose `length` bytes of JSON the bridge wrote at
/// `sb_input()`.
#[unsafe(no_mangle)]
pub extern "C" fn sb_event(kind: u32, length: usize) {
    app().event(kind, length);
}

/// Returns where the bridge writes an event.
#[unsafe(no_mangle)]
pub extern "C" fn sb_input() -> *mut u8 {
    app().input().as_mut_ptr()
}

/// Returns the largest event, in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_input_capacity() -> usize {
    INPUT_LIMIT
}

/// Returns the rendered page's UTF-8 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_html() -> *const u8 {
    app().html().as_ptr()
}

/// Returns the rendered page's length in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_html_length() -> usize {
    app().html().len()
}

/// Returns the command list's UTF-8 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_commands() -> *const u8 {
    app().commands().as_ptr()
}

/// Returns the command list's length in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_commands_length() -> usize {
    app().commands().len()
}

/// Returns where the bridge writes the downloaded geometry.
#[unsafe(no_mangle)]
pub extern "C" fn sb_geometry_input() -> *mut u8 {
    app().geometry_input().as_mut_ptr()
}

/// Returns the largest geometry file, in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_geometry_capacity() -> usize {
    geometry::MAX_BYTES
}

/// Takes the `length` bytes of geometry the bridge wrote (0 after a failed download).
#[unsafe(no_mangle)]
pub extern "C" fn sb_geometry_loaded(length: usize) {
    app().geometry_loaded(length);
}

/// Draws an animation frame at `milliseconds` and returns its length (0 for none).
#[unsafe(no_mangle)]
pub extern "C" fn sb_frame(milliseconds: f64) -> usize {
    app().frame(milliseconds)
}

/// Returns the latest animation frame's UTF-8 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sb_frame_html() -> *const u8 {
    app().frame_html().as_ptr()
}
