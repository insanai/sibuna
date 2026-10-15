//! The application: state, modules, the live connection and the buffers the bridge reads.
//!
//! Each browser call runs one pass: [`App::event`] erases the previous command list,
//! dispatches the event, reconciles routes and subscriptions, renders the whole page and
//! leaves the page text and the command list for the bridge to read.

use sibuna_console_protocol::ranking_history;
use sibuna_json::Value;

use crate::commands::Commands;
use crate::dispatch;
use crate::geometry;
use crate::live::{self, Connection};
use crate::page::{Context, Pages, View};
use crate::render::{self, Html, RENDER_LIMIT};
use crate::routing;
use crate::state::State;
use crate::wipe::{wipe_bytes, wipe_string};
use crate::{json, pages};

/// The largest event the bridge may deliver, in bytes: the largest server reply (a
/// retained rankings archive in hexadecimal) plus the event envelope. The bridge refuses
/// longer replies before they reach the module.
pub const INPUT_LIMIT: usize = ranking_history::EVENT_BYTES;

/// The kinds of browser event, numbered as `glue.js` numbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// 1: a button, link or form submission: `{"action": .., "fields": {..}}`.
    Action,
    /// 2: a server reply: `{"id": .., "status": .., "body": ..}`.
    Response,
    /// 3: a timer fired: `{"id": ..}`.
    Timer,
    /// 4: the WebSocket opened, closed or delivered a message.
    Stream,
    /// 5: the tab was hidden or shown: `{"hidden": ..}`.
    Visibility,
    /// 7: the reduced-motion preference: `{"reduced_motion": ..}`.
    Motion,
    /// 8: the URL fragment changed: `{"route": ..}`.
    Route,
    /// 9: the saved appearance and the system theme at start-up.
    Appearance,
    /// 10: the system theme changed.
    SystemTheme,
}

impl EventKind {
    /// Returns the kind numbered `code`, or `None` for an unknown number (6 is unused).
    pub fn from_code(code: u32) -> Option<EventKind> {
        Some(match code {
            1 => EventKind::Action,
            2 => EventKind::Response,
            3 => EventKind::Timer,
            4 => EventKind::Stream,
            5 => EventKind::Visibility,
            7 => EventKind::Motion,
            8 => EventKind::Route,
            9 => EventKind::Appearance,
            10 => EventKind::SystemTheme,
            _ => return None,
        })
    }
}

/// The whole interface. The WebAssembly exports drive one instance; native tests drive
/// their own.
#[derive(Debug)]
pub struct App {
    state: State,
    pages: Pages,
    live: Connection,
    commands: Commands,
    /// The bridge writes each event here, at most [`INPUT_LIMIT`] bytes.
    input: Vec<u8>,
    /// The rendered page; empty after a render that exceeded the bound.
    html: String,
    /// The latest animation frame.
    frame: String,
    /// `start` has run; events before it are ignored.
    started: bool,
}

impl Default for App {
    fn default() -> App {
        App::new()
    }
}

impl App {
    /// Returns an application with every page of this build registered, not yet started.
    pub fn new() -> App {
        App::with_pages(pages::load_pages())
    }

    /// Returns an application with the given modules, not yet started.
    pub fn with_pages(pages: Pages) -> App {
        App {
            state: State::new(),
            pages,
            live: Connection::default(),
            commands: Commands::default(),
            input: vec![0; INPUT_LIMIT],
            html: String::new(),
            frame: String::new(),
            started: false,
        }
    }

    /// Starts the interface (`sb_init`): a fresh state at the loading phase and a session
    /// check.
    pub fn start(&mut self) {
        self.live = Connection::default();
        self.state = State::new();
        self.pages.reset_all();
        self.started = true;
        self.commands.begin();
        // Writing into the owned command list cannot fail.
        let _ = self.commands.get("session", "/console/api/session");
        self.finish();
    }

    /// Returns true once [`App::start`] has run.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Returns the buffer the bridge writes events into ([`INPUT_LIMIT`] bytes).
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }

    /// Handles the event of kind `code` whose JSON text the bridge wrote into the first
    /// `length` bytes of [`App::input`]. Ignored before [`App::start`] and when `length`
    /// exceeds the input. The input is erased afterwards.
    pub fn event(&mut self, code: u32, length: usize) {
        if !self.started || length > self.input.len() {
            return;
        }
        let input = std::mem::take(&mut self.input);
        if let Some(text) = input.get(..length) {
            self.commands.begin();
            match sibuna_json::parse_with_limits(text, &json::limits(INPUT_LIMIT)) {
                Ok(value) => self.dispatch(EventKind::from_code(code), &value),
                Err(_) => self.state.set_message("Could not read the response. Please reconnect."),
            }
            self.finish();
        }
        self.input = input;
        if let Some(used) = self.input.get_mut(..length) {
            wipe_bytes(used);
        }
    }

    /// Copies `text` into the input and handles it as an event of kind `code`, as the
    /// bridge does; for native callers and tests.
    pub fn send(&mut self, code: u32, text: &str) {
        let Some(slot) = self.input.get_mut(..text.len()) else { return };
        slot.copy_from_slice(text.as_bytes());
        self.event(code, text.len());
    }

    fn dispatch(&mut self, kind: Option<EventKind>, value: &Value<'_>) {
        let previous = self.state.phase;
        let mut cx = self.context();
        if dispatch::event(&mut cx, kind, value).is_err() {
            cx.state.set_message("Could not complete the action. Please try again.");
            cx.state.busy = false;
        }
        if let Some(name) = routing::take(cx.state)
            && dispatch::action(&mut cx, name, &Value::Null).is_err()
        {
            cx.state.set_message("Could not open this page. Please try again.");
        }
        if self.state.phase != previous {
            self.pages.left(&mut self.state, previous);
            self.state.navigation_open = false;
            // Writing into the owned command list cannot fail.
            let _ = self.commands.focus_top("main h1");
        }
    }

    fn context(&mut self) -> Context<'_> {
        Context {
            state: &mut self.state,
            commands: &mut self.commands,
            pages: &mut self.pages,
            live: &mut self.live,
        }
    }

    /// Ends an event: routes, subscriptions, the age timer and the modules' end-of-event
    /// work, then the command list is closed and the page rendered.
    fn finish(&mut self) {
        let mut cx = self.context();
        // Writes into the owned command list cannot fail.
        let _ = routing::sync(cx.state, cx.commands);
        if live::sync(&mut cx).is_err() {
            cx.state.set_message("Live connection unavailable. Reload to retry.");
        }
        if cx.state.is_full_access() && !cx.state.hidden {
            let _ = cx.commands.timer("age", 1000);
        }
        // A module records its own failure; one failing module does not stop the others.
        let _ = cx.each(&mut |page, cx| {
            let _ = page.finish(cx);
            Ok(false)
        });
        self.commands.end();
        self.render();
    }

    fn render(&mut self) {
        // The previous page may show an authenticator seed or recovery codes.
        wipe_string(&mut self.html);
        let view = View { state: &self.state, pages: &self.pages };
        let mut out = Html::new(&mut self.html, RENDER_LIMIT);
        if render::render(&view, &mut out).is_err() {
            wipe_string(&mut self.html);
        }
    }

    /// Returns the geometry buffer for the bridge to download into.
    pub fn geometry_input(&mut self) -> &mut [u8] {
        self.state.geometry.input()
    }

    /// Takes the geometry the bridge downloaded (`length` bytes; 0 after a failure). The
    /// geometry is kept only on the dashboard of a session with full access; invalid
    /// geometry delays the next download by 30 seconds.
    pub fn geometry_loaded(&mut self, length: usize) {
        if !self.started {
            return;
        }
        self.commands.begin();
        let state = &mut self.state;
        state.geometry.busy = false;
        let wanted = state.phase == crate::state::Phase::Dashboard && state.is_full_access();
        if wanted && length <= geometry::MAX_BYTES {
            match state.geometry.load(length) {
                Ok(()) => state.geometry.retry_at = 0,
                Err(_) => state.geometry.retry_at = state.browser_time.saturating_add(30),
            }
        } else {
            state.geometry.unload();
        }
        self.finish();
    }

    /// Draws an animation frame at `milliseconds` (the browser's frame clock) and returns
    /// its length, or 0 when there is none.
    pub fn frame(&mut self, milliseconds: f64) -> usize {
        if !self.started {
            return 0;
        }
        wipe_string(&mut self.frame);
        self.pages.frame(&mut self.state, milliseconds, &mut self.frame)
    }

    /// Returns the latest animation frame.
    pub fn frame_html(&self) -> &str {
        &self.frame
    }

    /// Returns the rendered page.
    pub fn html(&self) -> &str {
        &self.html
    }

    /// Returns the command list of the last call, a JSON array.
    pub fn commands(&self) -> &str {
        self.commands.as_str()
    }

    /// Returns the shared state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Returns the shared state for changes; for tests and golden fixtures that set up a
    /// scene directly.
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Returns the registered modules.
    pub fn pages(&self) -> &Pages {
        &self.pages
    }

    /// Returns the registered modules for changes; for tests and golden fixtures.
    pub fn pages_mut(&mut self) -> &mut Pages {
        &mut self.pages
    }

    /// Renders the page again without an event; for golden fixtures that set state
    /// directly.
    pub fn render_now(&mut self) -> &str {
        self.render();
        &self.html
    }
}

#[cfg(test)]
mod tests;
