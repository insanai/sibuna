//! The Sibuna console interface: a WebAssembly module that owns every page, all
//! interface state and every fragment of markup (SID 0007, "The Interface Module").
//!
//! `web/glue.js` is the fixed browser bridge. It moves browser events into the module as
//! JSON, reads back the whole page as HTML and a list of commands, patches the page and
//! runs the commands (fetch, WebSocket, timers, focus, history, clipboard, downloads).
//! No markup, route or form logic lives in JavaScript, so the same crate runs natively for
//! the golden tests. The crate is a `cdylib` for `wasm32-unknown-unknown` and an `rlib`.
//!
//! # The bridge (ABI)
//!
//! The exports keep the Zig names and meanings, so `glue.js` is Zig's bridge except for
//! comments and one fix: an event longer than [`INPUT_LIMIT`] is replaced by a small one
//! instead of being dropped (see "Bounds and budget"). All exports live in the `abi`
//! module, the only module with `unsafe` code.
//!
//! - `sb_init()`: start at the loading phase and request `GET /console/api/session`.
//! - `sb_input() -> *mut u8` and `sb_input_capacity()`: where the bridge writes an event,
//!   at most [`INPUT_LIMIT`] bytes.
//! - `sb_event(kind, length)`: handle the event in the input; [`EventKind`] numbers it.
//! - `sb_html()` and `sb_html_length()`: the rendered page, UTF-8.
//! - `sb_commands()` and `sb_commands_length()`: the JSON array of commands of the last
//!   call.
//! - `sb_geometry_input()`, `sb_geometry_capacity()` and `sb_geometry_loaded(length)`:
//!   the world boundaries download ([`geometry`]).
//! - `sb_frame(ms) -> length` and `sb_frame_html()`: one globe animation frame.
//!
//! Every event the bridge sends carries `browser_time` (Unix seconds), and stream events
//! carry `entropy` (a random `u32` for the reconnect jitter). The command objects are
//! listed in [`commands`]. The exports that return addresses never allocate: the bridge
//! reads `memory.buffer` before calling them, and growing memory would detach it.
//!
//! # Architecture
//!
//! - [`App`] owns everything: the shared [`State`], the registered page modules
//!   ([`Pages`]), the live [`live::Connection`], the [`commands::Commands`] of the current
//!   call, the event input and the rendered page.
//! - One call is one pass ([`App::event`]): erase the previous command list; parse the
//!   event (bounded by [`INPUT_LIMIT`]); dispatch it (the core's handlers and the
//!   modules', see below); open a pending bookmarked route; if the phase changed, tell the
//!   modules ([`Page::left`]), close the navigation drawer and move focus to `main h1`;
//!   then [`routing::sync`] (history), [`live`] synchronisation (connection and
//!   subscriptions), the one-second `age` timer and every module's [`Page::finish`];
//!   finally render the whole page into a reused string bounded by
//!   [`render::RENDER_LIMIT`]. The input is erased after the call.
//! - The core handles authentication (session, setup, sign-in, password change, sign-out,
//!   wall-display code exchange), the navigation drawer, appearance, pause, the live
//!   stream and statistics ([`stats`]), the geometry download, routes and the shell. Its
//!   fallbacks run after the modules: an action or reply no module claims reaches the
//!   core.
//! - The render pipeline ([`render`]): signed-out phases draw the authentication card; a
//!   wall display draws the [`Screen::Kiosk`] module without the shell; otherwise the
//!   navigation shell ([`shell`]) surrounds the module whose [`Page::screen`] is the
//!   current phase. A phase without a registered module (only a test registry has one)
//!   draws a placeholder heading ("This page is not available in this build").
//! - Shared helpers for pages: [`render::message`], [`render::field`],
//!   [`render::statistics_tabs`], [`live::render_status`], [`format`](mod@format) (counts with
//!   separators, Zig-identical decimals, timestamps, deviations), [`scope`] (the live
//!   view's name and status), [`json`] (reading event members), and the generated
//!   snippet functions in `snippets` (`snippets::render_<stem>` with
//!   `snippets::<Stem>Values`).
//!
//! # The page interface
//!
//! A page module is a type that implements [`Page`] and owns its state. It is registered
//! with one line in `pages/mod.rs` (plus its `mod` declaration):
//!
//! ```ignore
//! let pages: Vec<Box<dyn Page>> = vec![
//!     Box::new(AccountSecurity::default()),
//!     Box::new(Nodes::default()),          // the new line
//! ];
//! ```
//!
//! The core calls the modules in registration order; every method has a default that does
//! nothing except [`Page::reset`]:
//!
//! - [`Page::screen`]: the [`Screen`] the module draws (`Phase(..)`, `Kiosk`,
//!   `AccountPanel`); Zig's phase switch in `render.zig`.
//! - [`Page::render`]: draw that screen into [`render::Html`] from a [`View`]; the
//!   `render` of a `*_page.zig`.
//! - [`Page::action`]: an operator action `name` with form `fields`; `Ok(true)` claims
//!   it. The `action` of a `*_controller.zig`.
//! - [`Page::response`]: a server [`Reply`]; claim replies by the id prefix the module
//!   chose. The controller's `response`, and `boundedEnvelope` in `main.zig`.
//! - [`Page::timer`]: a browser timer, including the one-second `age` tick; `Ok(true)`
//!   stops later modules. The kind-3 branch of `main.zig`.
//! - [`Page::input_too_large`]: the bridge refused the module's form action because its
//!   event exceeded [`INPUT_LIMIT`]; explain what to do instead (new in the Rust port).
//! - [`Page::resume`]: the tab became visible (the kind-5 branch).
//! - [`Page::stats_received`]: a live snapshot was accepted on the dashboard or the
//!   Nodes page (`refreshRankings`, `refreshTimeline`).
//! - [`Page::subscription`]: the filter wanted for a live topic now, or `None`
//!   (`live_controller.desired`).
//! - [`Page::publish`]: a completed live view of a topic other than `stats`
//!   (`live_controller.publish`).
//! - [`Page::connection_lost`]: the WebSocket failed (`state.challenges.stale = true`).
//! - [`Page::left`]: the phase changed from `from`; erase one-time values (the
//!   `clearSecret` calls in `sb_event`).
//! - [`Page::finish`]: the end of every event, before rendering (`kiosk_grant.retain`,
//!   `traffic_period_controller.sync`).
//! - [`Page::reset`]: sign-out or an expired session; drop everything (`State.reset`).
//! - [`Page::frame`]: an animation frame, for the globe (`globe_motion.frame`); it may
//!   advance shared view state, as the globe's turn.
//! - [`Page::shown_signed_out`]: the module's screen stays on although the session is
//!   signed out (the recovery codes after two-factor enrollment ended the session).
//!
//! Handlers get a [`Context`]: `cx.state` (the shared [`State`]), `cx.commands`, and
//! `cx.pages` (every other module, reachable with [`Pages::find`] and
//! [`Pages::find_mut`] by type; the running module is taken out while it runs). Helpers:
//! [`Context::get`], [`Context::post`] (adds the CSRF token), [`Context::post_value`] for
//! any [`sibuna_console_protocol::codec::Encode`] body, [`Context::action`] (offer an
//! action to the other modules, for example to open another page), [`Context::with_page`]
//! (take one other module out and call it, as the security overview opens an
//! investigation on the Events page), [`Context::disconnect`], [`Context::reset_session`]
//! and [`Context::end_session`]. Rules that keep modules independent:
//!
//! - The core moves focus to `main h1` after any phase change; a module never emits that
//!   focus itself (Zig's bounded-envelope handlers did, for their own phase changes).
//! - Live subscriptions are reconciled once per event, after dispatch, from
//!   [`Page::subscription`]; there is no explicit "refresh" to call.
//! - A reply without an integer status or without a body still reaches the modules
//!   ([`Reply::complete`] returns `None`); ordinary handlers return `Ok(true)` for their
//!   own ids and ignore it, as Zig did by returning early.
//! - `cx.state.browser_time` is set from every event before dispatch.
//! - An `Err` from a handler shows "Could not complete the action. Please try again." and
//!   clears `state.busy`, as Zig's error unions did; set a more specific message with
//!   [`State::set_message`] and return `Ok(true)` instead where Zig did so.
//! - Panels shared by several pages (the globe, the timeline, the traffic tiles) are
//!   modules without a screen; the pages that draw them call their render functions
//!   through [`Pages::find`] on [`View::pages`]. Decision tones, metric names and the
//!   counter sparkline that several pages draw are in [`charts`].
//! - One session-expiry rule: a reply that refuses the session (401, or the 403 of a read
//!   whose page has no role message) calls [`Context::end_session`]. The bridge closes
//!   the live connection and cancels every timer, the shared state and every module are
//!   reset to sign-in, the appearance (theme and density) survives, and the operator
//!   reads why. Zig's pages differed: some reset the appearance, some kept page state.
//!
//! # How to add a page
//!
//! Every page of the Zig module is ported and registered in `pages/mod.rs`, in the order
//! `main.zig` consulted its controllers (actions: kiosk, dashboard node, policy audit
//! link, management, managed policies, incident addresses, policies, similarity,
//! challenges, events, account, geography; replies: similarity, events, challenges,
//! incident heads, management prefixes, rankings/timeline/minutes, policies, account,
//! events export, GeoIP).
//!
//! The worked example is [`pages::AccountSecurity`], ported from `security.zig` and
//! `account_security_controller.zig` with the fixtures `security.html` and
//! `required-totp.html`:
//!
//! 1. Create `src/pages/<name>.rs` (or a directory with submodules). Move the page's
//!    fields out of the Zig `State` into a struct that derives `Default`; Zig `Bytes(N)`
//!    become [`sibuna_console_protocol::Text`] (or [`secret::Secret`] for credentials),
//!    fixed arrays with a count become `Vec`s with the same bound.
//! 2. Implement [`Page`]: `screen` returns `Some(Screen::Phase(Phase::<phase>))`; move the
//!    `*_page.zig` render into `render`, writing literal markup with `write_str`, values
//!    with [`sibuna_html::write_value`] or [`render::Html::escaped`], numbers with
//!    [`format`](mod@format), and snippet files through the generated `snippets::render_*`
//!    functions; move the controller's branches of `main.zig` into `action`, `response`
//!    and `timer`. Keep request ids and paths byte for byte; the bridge and the server
//!    depend on them.
//! 3. Write `reset` (`*self = Self::default()`), and `left` if the page shows one-time
//!    values.
//! 4. Register the module in `pages/mod.rs`, at its place in the dispatch order above.
//! 5. Port the Zig tests into the module's `tests` (drive the whole application with
//!    `testing::Harness` and its JSON events, or call the module directly), and port the
//!    fixture: build the scene with `golden::configure` and the state setters (or with
//!    recorded events), call `golden::check("<fixture>", app.render_now())`, and list the
//!    fixture in `golden::CHECKED`.
//! 6. Run `cargo test`, `cargo clippy --all-targets`, `cargo xtask check cmd/console-ui`,
//!    and the WebAssembly build below, and note the module size.
//!
//! The example's shape, abbreviated:
//!
//! ```ignore
//! #[derive(Debug, Default)]
//! pub struct AccountSecurity {
//!     pub available: Option<bool>,
//!     pub secret: Secret<32>,
//!     pub recovery_codes: Vec<Secret<32>>,
//!     // ...
//! }
//!
//! impl Page for AccountSecurity {
//!     fn screen(&self) -> Option<Screen> {
//!         Some(Screen::Phase(Phase::Security))
//!     }
//!     fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
//!         out.write_str("<main class=\"sb-auth\"><section class=\"sb-auth-card\">...")?;
//!         render::message(view.state, out)?;
//!         // ...
//!     }
//!     fn action(&mut self, cx: &mut Context<'_>, name: &str, fields: &Value<'_>)
//!         -> Result<bool, UiError> {
//!         if name == "security" && !cx.state.csrf.is_empty() {
//!             cx.state.phase = Phase::Security;
//!             self.available = None;
//!             cx.state.busy = true;
//!             cx.get("totp", "/console/api/totp")?;
//!             return Ok(true);
//!         }
//!         // ...
//!     }
//!     fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>)
//!         -> Result<bool, UiError> {
//!         if !reply.id.starts_with("totp") {
//!             return Ok(false);
//!         }
//!         let Some((status, body)) = reply.complete() else { return Ok(true) };
//!         // ...
//!     }
//!     fn reset(&mut self) {
//!         *self = AccountSecurity::default();
//!     }
//! }
//! ```
//!
//! # Bounds and budget
//!
//! - Events: at most [`INPUT_LIMIT`] bytes (the largest retained rankings reply plus its
//!   envelope), which bounds the parsed event tree. The bridge replaces a longer event by
//!   a small one: a reply fails as a network error does (status 0), a stream message is
//!   invalid, and any other event, in practice a large form, arrives as
//!   [`EventKind::InputTooLarge`] with its action name, so the page can explain
//!   ([`Page::input_too_large`]) or the core shows a generic message. JSON nesting is
//!   limited to [`json::MAX_DEPTH`].
//! - Rendered page: at most [`render::RENDER_LIMIT`] (512 KiB), a sanity bound; a page that
//!   exceeds it is not shown.
//! - Geometry: [`geometry::MAX_BYTES`], [`geometry::MAX_RINGS`] rings,
//!   [`geometry::MAX_VERTICES`] vertices.
//! - Linear memory: at most 16 MiB (set by `build.rs`). The module starts with 1.5 MiB
//!   (mostly the 1 MiB stack); the worst event (the largest input, all small values)
//!   grows it to 3.6 MiB while its tree is parsed.
//! - Module size: SID 0007 sets a 768 KiB (786,432-byte) ceiling and a 640 KiB review
//!   threshold. Build with
//!   `cargo build -p sibuna-console-ui --target wasm32-unknown-unknown --profile wasm`
//!   (the workspace's `wasm` profile: `opt-level = "z"`, fat LTO, stripped, panics
//!   abort); `build.rs` adds the linker's `--compress-relocations` when there is no debug
//!   information. With every page the module is 720,111 bytes (270,853 gzipped), above
//!   the review threshold. What brought it under the ceiling from 936,750 bytes with the
//!   old release profile: the `wasm` profile, shortest-form call targets and data
//!   addresses (about 55 KiB), trait-object writers for commands and dispatch, one
//!   function that ends every expired session, list decoding by loop instead of fallible
//!   `collect`, a sorted vector instead of a `BTreeMap` in the delta patcher, and one copy
//!   of the shared charts and parsers.
//!
//! # Assets
//!
//! `web/` holds the bridge (`glue.js`), the shell (`shell.html`, whose `{{ wasm }}`,
//! `{{ css }}` and `{{ glue }}` the server replaces with content digests), the Tailwind
//! source (`tailwind.css`) and the committed built assets in `web/assets`:
//! `console.css`, `world-110m.bin` (described in `GEOGRAPHY.md`) and the Zig build's
//! digest list `MANIFEST.md`. The build never runs npm. Regenerating `console.css` after a
//! change to `tailwind.css` is a manual step that needs the Tailwind CLI 4.1.13 with
//! daisyUI 5.1.13: `npx @tailwindcss/cli -i tailwind.css -o assets/console.css --minify`
//! in `web/`, then review and commit the result.
//!
//! # Golden fixtures
//!
//! `tests/golden/*.html` are the reviewed pages of the Zig module. The harness (`golden`,
//! a test module) compares rendered pages byte for byte and runs the mechanical principle
//! checks; `SIBUNA_UPDATE_CONSOLE_GOLDENS=1` rewrites fixtures after a reviewed change.
//! All 32 fixtures are listed in `golden::CHECKED` and match byte for byte.
//!
//! # Changes from the Zig module
//!
//! Behaviour, markup and bridge commands are the Zig module's; the fixtures prove the
//! markup. Mechanisms that existed only because Zig had no allocator in
//! `wasm32-freestanding`, or to manage memory by hand, are replaced:
//!
//! - Fixed buffers (512 KiB page, 16 KiB commands, 512 KiB event arena) became owned,
//!   reused `String`s and the parsed event tree. The bounds that protect something stay:
//!   the event input, the page size, the geometry size, JSON depth. The command list has
//!   no bound of its own: it is a function of the bounded input and bounded state (Zig
//!   failed an action whose commands exceeded 16 KiB, for example a large GeoIP CSV).
//! - `secureZero` on the event arena and the enrollment page became a WebAssembly
//!   allocator that zeroes every block it frees, plus explicit wiping of the reused input,
//!   page and command buffers; [`secret::Secret`] replaces credentials instead of
//!   overwriting them in place.
//! - The `State.reset` loop over the compiler's field enum (to avoid a second state image
//!   in the module's data) became `*self = State::new()`, and page state moved into the
//!   page modules, each with its own [`Page::reset`].
//! - The module-level variables of `live_controller.zig` and `main.zig` became
//!   [`live::Connection`] and [`App`]; `sb_init` resets them.
//! - The `json_value.zig` reflection decoder is replaced by the protocol crate's
//!   [`sibuna_console_protocol::codec::Decode`] and the [`json`] helpers. Live statistics
//!   views decode as `dashboard::View`, which rejects members it does not know where Zig
//!   ignored them; a refused view restarts the connection like any invalid view. A counter
//!   sent as a string is read as the protocol reads integers (Zig's `sliceToInt`), so `"+1"`
//!   and `"1e3"` are accepted where the Zig decoder refused them; whether the value is a
//!   whole number is decided exactly on the text, never through a float.
//! - Explicit `refresh()` calls became the once-per-event subscription reconciliation, so
//!   commands may appear later in the list than in Zig; their set is the same.
//! - The geometry is forgotten as soon as the bridge asks for the buffer again, and when a
//!   download arrives on another page; Zig kept a slice into bytes being overwritten.
//! - A pending authenticator seed is erased when the operator leaves the two-factor page
//!   ([`Page::left`]); Zig erased it on the next visit or on the `account` action.
//! - Linear memory grows on demand up to 16 MiB instead of a fixed 4 MiB.
//! - Every session expiry follows one rule ([`Context::end_session`]) and keeps the
//!   appearance; Zig's pages ended sessions in several ways.
//! - A policy set is imported with one request (`policies/import`, SID 0013) of at most
//!   128 documents and 256 KiB, instead of one request per document and a commit with a
//!   64 KiB limit; the review shows the set's SHA-256, the digest the audit row names.
//! - Confirming two-factor authentication drops the session token at once, as Zig did,
//!   but the recovery codes stay on screen until acknowledged ([`Page::shown_signed_out`]);
//!   Zig never showed them.
//! - The member card names a node's address the management address (SID 0013), not the
//!   consensus address.
//! - An event longer than [`INPUT_LIMIT`] is replaced by a small event instead of being
//!   dropped by the bridge, so a large pasted policy set (the import request allows
//!   256 KiB) is answered with a message naming the command-line import, not ignored.

#[cfg(target_arch = "wasm32")]
mod abi;
mod app;
pub mod appearance;
pub mod charts;
pub mod commands;
mod dispatch;
pub mod error;
pub mod format;
pub mod geometry;
pub mod json;
pub mod live;
pub mod page;
pub mod pages;
pub mod render;
pub mod routing;
pub mod scope;
pub mod secret;
pub mod shell;
pub mod state;
pub mod stats;
mod wipe;

#[cfg(test)]
mod golden;
#[cfg(test)]
mod testing;

/// The render functions `build.rs` generates from `src/snippets/*.html`, one per snippet
/// (`render_<stem>` with a `<Stem>Values` struct). Pages still being ported use most of
/// them, so unused ones are allowed.
#[allow(dead_code)]
pub(crate) mod snippets {
    include!(concat!(env!("OUT_DIR"), "/snippets.rs"));
}

pub use app::{App, EventKind, INPUT_LIMIT};
pub use error::UiError;
pub use page::{Context, Page, Pages, Reply, Screen, View};
pub use state::{Phase, State};
