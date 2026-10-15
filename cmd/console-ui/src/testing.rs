//! A native harness that drives the application the way `glue.js` does: JSON events in,
//! page HTML and command lists out (the Rust form of Zig's `test_transport.zig`).

use crate::app::App;
use crate::page::Pages;

/// An application started for a test, with helpers for each event kind.
pub struct Harness {
    /// The application under test.
    pub app: App,
}

impl Harness {
    /// Starts the application with every page of this build.
    pub fn new() -> Harness {
        Harness::with_pages(crate::pages::load_pages())
    }

    /// Starts the application with the given modules.
    pub fn with_pages(pages: Pages) -> Harness {
        let mut app = App::with_pages(pages);
        app.start();
        Harness { app }
    }

    /// Sends an action event (kind 1) with the form `fields` (JSON text).
    pub fn action(&mut self, name: &str, fields: &str) {
        let text =
            format!("{{\"action\":\"{name}\",\"fields\":{fields},\"browser_time\":172800}}");
        self.app.send(1, &text);
    }

    /// Sends a response event (kind 2) for request `id` with `status` and `body` (JSON).
    pub fn respond(&mut self, id: &str, status: i64, body: &str) {
        let text = format!(
            "{{\"id\":\"{id}\",\"status\":{status},\"body\":{body},\"browser_time\":172800}}"
        );
        self.app.send(2, &text);
    }

    /// Sends a stream event (kind 4).
    pub fn stream(&mut self, json: &str) {
        self.app.send(4, json);
    }

    /// Sends a raw event of kind `kind`.
    pub fn send(&mut self, kind: u32, json: &str) {
        self.app.send(kind, json);
    }

    /// Returns the command list of the last event.
    pub fn commands(&self) -> &str {
        self.app.commands()
    }

    /// Returns the rendered page.
    pub fn html(&self) -> &str {
        self.app.html()
    }
}

/// A configurable stand-in page for tests of the core: it opens its phase on its
/// navigation action, may send one request, subscribes one topic while shown, keeps a
/// draft that a session reset must erase, and records the views it receives.
#[derive(Debug, Default)]
pub struct Probe {
    /// The navigation action that opens the page.
    pub action: &'static str,
    /// The page's phase.
    pub phase: Option<crate::state::Phase>,
    /// A `GET` sent when the page opens: (id, path).
    pub request: Option<(&'static str, &'static str)>,
    /// The topic subscribed while the page is shown.
    pub topic: Option<sibuna_console_protocol::Topic>,
    /// A retained value that a session reset must erase.
    pub draft: String,
    /// The page body drawn for its phase.
    pub body: &'static str,
    /// Every published view, as JSON text.
    pub published: Vec<String>,
    /// Count of `left` calls with the page's phase.
    pub left: usize,
    /// The filter wanted for [`Probe::topic`].
    pub args: sibuna_console_protocol::subscriptions::Args,
}

impl crate::page::Page for Probe {
    fn screen(&self) -> Option<crate::page::Screen> {
        self.phase.map(crate::page::Screen::Phase)
    }

    fn render(
        &self,
        _view: &crate::page::View<'_>,
        out: &mut crate::render::Html<'_>,
    ) -> std::fmt::Result {
        use std::fmt::Write as _;
        out.write_str(self.body)
    }

    fn action(
        &mut self,
        cx: &mut crate::page::Context<'_>,
        name: &str,
        _fields: &sibuna_json::Value<'_>,
    ) -> Result<bool, crate::error::UiError> {
        let Some(phase) = self.phase else { return Ok(false) };
        if name != self.action || !cx.state.is_full_access() {
            return Ok(false);
        }
        cx.state.phase = phase;
        if let Some((id, path)) = self.request {
            cx.get(id, path)?;
        }
        Ok(true)
    }

    fn subscription(
        &self,
        state: &crate::state::State,
        topic: sibuna_console_protocol::Topic,
    ) -> Option<sibuna_console_protocol::subscriptions::Args> {
        (Some(topic) == self.topic && Some(state.phase) == self.phase).then(|| self.args.clone())
    }

    fn publish(
        &mut self,
        _cx: &mut crate::page::Context<'_>,
        topic: sibuna_console_protocol::Topic,
        view: &sibuna_json::Value<'_>,
    ) -> Result<(), crate::error::UiError> {
        if Some(topic) == self.topic {
            self.published.push(view.to_string());
        }
        Ok(())
    }

    fn left(&mut self, _state: &mut crate::state::State, from: crate::state::Phase) {
        if Some(from) == self.phase {
            self.left += 1;
        }
    }

    fn reset(&mut self) {
        self.draft.clear();
        self.published.clear();
    }
}

/// Returns a registry of the account security page and `probes`.
pub fn with_probes(probes: Vec<Probe>) -> Pages {
    let mut pages: Vec<Box<dyn crate::page::Page>> =
        vec![Box::new(crate::pages::AccountSecurity::default())];
    for probe in probes {
        pages.push(Box::new(probe));
    }
    Pages::new(pages)
}

/// A signed-in session reply for an administrator of node 1.
pub const ADMIN_SESSION: &str =
    "{\"user\":1,\"csrf\":\"test\",\"node\":1,\"role\":\"admin\",\"must_change\":false}";
