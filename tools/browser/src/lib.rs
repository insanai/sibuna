//! Drives headless Chromium over the Chrome DevTools Protocol, for Sibuna's browser checks.
//!
//! [`Browser::launch`] starts `chromium --headless=new` with a private temporary profile
//! and `--remote-debugging-port=0`, reads the port Chromium chose from
//! `<profile>/DevToolsActivePort`, and opens the browser's WebSocket with
//! `std::net::TcpStream`. [`Browser::new_page`] opens a tab and attaches to it as a
//! flattened session (`Target.attachToTarget` with `flatten: true`), so one socket carries
//! every command and event. A [`Page`] navigates, evaluates and waits for expressions,
//! clicks, types, takes screenshots, sets the viewport, reads cookies, records screencast
//! frames, holds chosen requests, and removes WebAssembly on demand. It collects console
//! messages, exceptions (its workers' too), network failures and document responses so a
//! check can assert that nothing went wrong.
//!
//! ```no_run
//! use std::path::Path;
//! use std::time::Duration;
//! use sibuna_browser::{Browser, Options};
//!
//! let mut browser = Browser::launch(Options::default())?;
//! let mut page = browser.new_page()?;
//! page.set_viewport(1280, 800, false)?;
//! page.navigate("http://127.0.0.1:8080/")?;
//! page.wait_for("document.querySelector('h1') !== null", Duration::from_secs(5))?;
//! page.screenshot(Path::new("page.png"))?;
//! assert!(page.exceptions().is_empty());
//! # Ok::<(), sibuna_browser::Error>(())
//! ```
//!
//! Every wait has a deadline: launching ([`Options::launch_timeout`]), each command
//! ([`Options::command_timeout`]), and [`Page::wait_for`]. Messages are bounded by
//! [`Options::max_message_bytes`] and the collected records by a fixed count. Dropping the
//! [`Browser`] closes Chromium, kills it if it lingers, and removes the profile.
//!
//! The crate uses no external crates: WebSocket frames and the accept key come from
//! `sibuna-http`, JSON from `sibuna-json`, and base64 from `sibuna-encoding`.
//!
//! # Changes from the Zig repository
//!
//! The Zig repository checked the browser side with Node and Python:
//! `tools/console_ui_driver.mjs` ran the console's WebAssembly in Node, and
//! `tools/console_ui_live_test.py` fed it events from a live daemon, leaving "Chrome
//! separately verifies the real DOM" to manual runs. This crate replaces those drivers
//! with a real browser driven from Rust, as SID 0010 asks:
//!
//! - The checks run in Chromium itself, so the DOM, the Content-Security-Policy, Web
//!   Workers and WebAssembly are the ones visitors get, not a Node approximation.
//! - Video is a numbered PNG sequence from `Page.startScreencast` with a `frames.txt`
//!   index, since no encoder is available; any tool can assemble it later.
//! - The incoming WebSocket decoder is local (`src/websocket.rs`) because
//!   `sibuna-http`'s reader bounds messages at 4 KiB for the edge, while DevTools sends
//!   screenshots of megabytes in one frame. Outgoing frames use `sibuna-http`'s encoder,
//!   fragmented into 4 KiB pieces, which Chromium reassembles.
//! - WebAssembly is removed with [`Page::disable_webassembly`], which deletes the global
//!   in every document and dedicated worker before their scripts run. V8's
//!   `--js-flags=--noexpose_wasm` was the planned switch, but Chromium 155 ignores it.
//!
//! Two DevTools details shaped the design. Chromium sends the next screencast frame, and
//! paints the frame a screenshot waits for, only after the previous frame is
//! acknowledged; so the connection acknowledges frames the moment they arrive, even while
//! a command is outstanding. And a challenge solves in tens of milliseconds, too fast to
//! photograph; [`Page::hold_requests`] holds the verification request so the interstitial
//! can be captured, and the check subtracts the hold from its timings.

mod browser;
pub mod cdp;
mod connection;
mod error;
mod page;
mod websocket;

pub use browser::{Browser, Options};
pub use error::Error;
pub use page::{
    BindingCall, ConsoleMessage, Cookie, DocumentResponse, Evaluated, Exception, HeldRequest,
    NetworkFailure, Page, Recording, RecordingOptions,
};
