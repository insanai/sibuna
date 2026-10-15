//! One browser tab, attached as a flattened DevTools session.

mod evaluated;
mod observe;
mod recorder;
mod workers;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use sibuna_encoding::base64;
use sibuna_json::Value;

use crate::browser::Browser;
use crate::cdp::{Message, MessageKind, Params, field, string_at};
use crate::error::Error;

pub use evaluated::Evaluated;
pub use observe::{
    BindingCall, ConsoleMessage, DocumentResponse, Exception, HeldRequest, NetworkFailure,
};
pub use recorder::{Recording, RecordingOptions};

use observe::Observations;
use recorder::Recorder;

/// How often [`Page::wait_for`] evaluates its condition.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The domains whose events a page reports.
const DOMAINS: [&str; 4] = ["Page.enable", "Runtime.enable", "Log.enable", "Network.enable"];

/// A cookie of the page's current URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
    /// The domain it is sent to.
    pub domain: String,
    /// The path it is sent to.
    pub path: String,
    /// True when scripts cannot read it.
    pub http_only: bool,
    /// True when it is sent over HTTPS only.
    pub secure: bool,
}

/// A tab driven over DevTools. It borrows its [`Browser`] mutably, so only one page is
/// driven at a time; dropping it closes the tab.
///
/// Events are collected whenever the page talks to Chromium: during every command, during
/// [`Page::wait_for`] and [`Page::idle_for`]. Console messages and exceptions of the
/// page's dedicated workers are collected too. After [`Page::add_worker_script`], new
/// workers wait until the page processes their attachment, so a page that is not being
/// driven then pauses its new workers.
#[derive(Debug)]
pub struct Page<'b> {
    browser: &'b mut Browser,
    target_id: String,
    session_id: String,
    observations: Observations,
    recorder: Option<Recorder>,
    /// Sessions of the dedicated workers we observe.
    workers: Vec<String>,
    /// Scripts run in each new worker before its own.
    worker_scripts: Vec<String>,
}

impl<'b> Page<'b> {
    /// Creates a blank tab, attaches to it with `flatten: true` and enables the domains
    /// whose events the page reports.
    pub(crate) fn open(browser: &'b mut Browser) -> Result<Page<'b>, Error> {
        let created =
            browser.call("Target.createTarget", &Params::new().string("url", "about:blank"))?;
        let target_id = string_at(&created.body()?, &["result", "targetId"]).to_owned();
        let params = Params::new().string("targetId", &target_id).bool("flatten", true);
        let attached = browser.call("Target.attachToTarget", &params)?;
        let session_id = string_at(&attached.body()?, &["result", "sessionId"]).to_owned();
        if target_id.is_empty() || session_id.is_empty() {
            return Err(Error::Protocol("no target or session id for the new page".into()));
        }
        let mut page = Page {
            browser,
            target_id,
            session_id,
            observations: Observations::default(),
            recorder: None,
            workers: Vec::new(),
            worker_scripts: Vec::new(),
        };
        for method in DOMAINS {
            page.call(method, &Params::new())?;
        }
        page.begin_auto_attach(false)?;
        Ok(page)
    }

    /// Sends any DevTools command to this page's session and waits for its response, for
    /// what the typed methods do not cover.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when Chromium refuses it, [`Error::Timeout`] after the command
    /// timeout, and connection errors.
    pub fn call(&mut self, method: &str, params: &Params) -> Result<Message, Error> {
        let deadline = Instant::now() + self.browser.options.command_timeout;
        self.call_until(method, params, deadline)
    }

    fn call_until(
        &mut self,
        method: &str,
        params: &Params,
        deadline: Instant,
    ) -> Result<Message, Error> {
        let reply = self.browser.connection.call(Some(&self.session_id), method, params, deadline);
        // Events that arrived during the command are processed even when it failed.
        let drained = self.process_events_until(Instant::now());
        let reply = reply?;
        drained?;
        Ok(reply)
    }

    /// Loads `url` and waits for its load event, up to the command timeout.
    ///
    /// # Errors
    ///
    /// [`Error::Navigation`] when no document could be loaded (an HTTP error status still
    /// loads one), and [`Error::Timeout`] when the load event does not come.
    pub fn navigate(&mut self, url: &str) -> Result<(), Error> {
        let loads = self.observations.load_count;
        let reply = self.call("Page.navigate", &Params::new().string("url", url))?;
        let body = reply.body()?;
        let error = string_at(&body, &["result", "errorText"]);
        if !error.is_empty() {
            return Err(Error::Navigation(format!("{url}: {error}")));
        }
        if string_at(&body, &["result", "loaderId"]).is_empty() {
            // A same-document navigation (a fragment change) fires no load event.
            return Ok(());
        }
        let timeout = self.browser.options.command_timeout;
        self.wait_until(&format!("the load event of {url}"), timeout, |seen| {
            seen.load_count > loads
        })
    }

    /// Evaluates `expression` in the page's main frame, awaiting a promise result, and
    /// returns the result as JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Evaluation`] when the expression throws or its promise rejects, and the
    /// errors of [`Page::call`].
    pub fn evaluate(&mut self, expression: &str) -> Result<Evaluated, Error> {
        let deadline = Instant::now() + self.browser.options.command_timeout;
        self.evaluate_until(expression, deadline)
    }

    fn evaluate_until(&mut self, expression: &str, deadline: Instant) -> Result<Evaluated, Error> {
        let params = Params::new()
            .string("expression", expression)
            .bool("returnByValue", true)
            .bool("awaitPromise", true);
        let reply = self.call_until("Runtime.evaluate", &params, deadline)?;
        let body = reply.body()?;
        if let Some(details) = field(&body, &["result", "exceptionDetails"]) {
            return Err(Error::Evaluation(observe::exception(Some(details)).text));
        }
        Ok(Evaluated::from_remote_object(field(&body, &["result", "result"])))
    }

    /// Evaluates `expression` every 25 ms until its value is truthy, and returns that value.
    /// Errors while polling (a context destroyed by a navigation, an element not there yet)
    /// count as "not yet".
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] after `timeout`, naming the last error seen; connection errors.
    pub fn wait_for(&mut self, expression: &str, timeout: Duration) -> Result<Evaluated, Error> {
        let started = Instant::now();
        let deadline = started + timeout;
        let mut last_error = None;
        loop {
            match self.evaluate_until(expression, deadline) {
                Ok(value) if value.is_truthy() => return Ok(value),
                Ok(_) => {}
                Err(
                    error @ (Error::Evaluation(_) | Error::Command { .. } | Error::Timeout { .. }),
                ) => {
                    last_error = Some(error.to_string());
                }
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                let what = format!("`{expression}` to become true");
                return Err(Error::Timeout { what, waited: started.elapsed(), last_error });
            }
            self.process_events_until((now + POLL_INTERVAL).min(deadline))?;
        }
    }

    /// Lets the page run for `duration`, collecting its events.
    ///
    /// # Errors
    ///
    /// Connection errors.
    pub fn idle_for(&mut self, duration: Duration) -> Result<(), Error> {
        self.process_events_until(Instant::now() + duration)
    }

    /// Clicks the centre of the first element matching the CSS `selector`, after scrolling
    /// it into view, with real mouse events.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when nothing matches, and the errors of [`Page::call`].
    pub fn click(&mut self, selector: &str) -> Result<(), Error> {
        let script = format!(
            "(() => {{ const e = document.querySelector({}); if (!e) return null; \
             e.scrollIntoView({{block: 'center', inline: 'center'}}); \
             const r = e.getBoundingClientRect(); \
             return [r.left + r.width / 2, r.top + r.height / 2]; }})()",
            js_string(selector)
        );
        let point = self.evaluate(&script)?;
        let value = point.value()?;
        let coordinates: Vec<f64> = value
            .as_array()
            .unwrap_or_default()
            .iter()
            .filter_map(|n| n.as_number().and_then(|n| n.as_f64().ok()))
            .collect();
        let [x, y] = coordinates[..] else { return Err(Error::NotFound(selector.to_owned())) };
        for (kind, button) in
            [("mouseMoved", "none"), ("mousePressed", "left"), ("mouseReleased", "left")]
        {
            let params = Params::new()
                .string("type", kind)
                .float("x", x)
                .float("y", y)
                .string("button", button)
                .int("clickCount", 1);
            self.call("Input.dispatchMouseEvent", &params)?;
        }
        Ok(())
    }

    /// Focuses the first element matching `selector` and inserts `text` as if typed,
    /// firing `input` events.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when nothing matches, and the errors of [`Page::call`].
    pub fn type_text(&mut self, selector: &str, text: &str) -> Result<(), Error> {
        let script = format!(
            "(() => {{ const e = document.querySelector({}); if (!e) return false; \
             e.focus(); return document.activeElement === e; }})()",
            js_string(selector)
        );
        if self.evaluate(&script)?.as_bool() != Some(true) {
            return Err(Error::NotFound(selector.to_owned()));
        }
        self.call("Input.insertText", &Params::new().string("text", text))?;
        Ok(())
    }

    /// Captures the viewport as PNG and writes it to `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] for invalid image data, [`Error::Io`] when writing fails, and
    /// the errors of [`Page::call`].
    pub fn screenshot(&mut self, path: &Path) -> Result<(), Error> {
        let reply = self.call("Page.captureScreenshot", &Params::new().string("format", "png"))?;
        let body = reply.body()?;
        let data = string_at(&body, &["result", "data"]);
        let png = base64::decode(base64::STANDARD, data.as_bytes())
            .map_err(|error| Error::Protocol(format!("screenshot data: {error}")))?;
        fs::write(path, png)
            .map_err(|error| Error::io(format!("writing {}", path.display()), error))
    }

    /// Emulates a viewport of `width` by `height` CSS pixels at scale 1, as a phone when
    /// `mobile` is set.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn set_viewport(&mut self, width: u32, height: u32, mobile: bool) -> Result<(), Error> {
        let params = Params::new()
            .int("width", i64::from(width))
            .int("height", i64::from(height))
            .int("deviceScaleFactor", 1)
            .bool("mobile", mobile);
        self.call("Emulation.setDeviceMetricsOverride", &params)?;
        Ok(())
    }

    /// The cookies the browser would send to the page's current URL.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn cookies(&mut self) -> Result<Vec<Cookie>, Error> {
        let reply = self.call("Network.getCookies", &Params::new())?;
        let body = reply.body()?;
        let list =
            field(&body, &["result", "cookies"]).and_then(Value::as_array).unwrap_or_default();
        let flag =
            |cookie: &Value<'_>, key| field(cookie, &[key]).and_then(Value::as_bool) == Some(true);
        Ok(list
            .iter()
            .map(|cookie| Cookie {
                name: string_at(cookie, &["name"]).to_owned(),
                value: string_at(cookie, &["value"]).to_owned(),
                domain: string_at(cookie, &["domain"]).to_owned(),
                path: string_at(cookie, &["path"]).to_owned(),
                http_only: flag(cookie, "httpOnly"),
                secure: flag(cookie, "secure"),
            })
            .collect())
    }

    /// Installs a global function `name(string)` in every document of the page, now and
    /// after navigations; each call is reported in [`Page::binding_calls`]. Page scripts
    /// can see it, so use a name they will not collide with.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn add_binding(&mut self, name: &str) -> Result<(), Error> {
        self.call("Runtime.addBinding", &Params::new().string("name", name))?;
        Ok(())
    }

    /// Runs `source` in every new document before the page's own scripts. DevTools scripts
    /// are not subject to the page's Content-Security-Policy.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn add_init_script(&mut self, source: &str) -> Result<(), Error> {
        let params = Params::new().string("source", source);
        self.call("Page.addScriptToEvaluateOnNewDocument", &params)?;
        Ok(())
    }

    /// Holds every later request whose URL matches `pattern` (`*` matches any run of
    /// characters, `?` one character) before it is sent, until [`Page::release_request`].
    /// A held request lets a check look at the page in a state that would otherwise pass
    /// too quickly to observe.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn hold_requests(&mut self, pattern: &str) -> Result<(), Error> {
        let item = Params::new().string("urlPattern", pattern).string("requestStage", "Request");
        let params = Params::new().array("patterns", &[item]);
        self.call("Fetch.enable", &params)?;
        Ok(())
    }

    /// Waits for the next held request.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] when none is held within `timeout`; connection errors.
    pub fn wait_for_held_request(&mut self, timeout: Duration) -> Result<HeldRequest, Error> {
        self.wait_until("a held request", timeout, |seen| !seen.held.is_empty())?;
        self.observations
            .held
            .pop_front()
            .ok_or_else(|| Error::Protocol("a held request vanished".into()))
    }

    /// Sends a held request on unchanged.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn release_request(&mut self, request: &HeldRequest) -> Result<(), Error> {
        self.call("Fetch.continueRequest", &Params::new().string("requestId", &request.id))?;
        Ok(())
    }

    /// Stops holding requests. Requests still held are released by Chromium.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`].
    pub fn stop_holding_requests(&mut self) -> Result<(), Error> {
        self.call("Fetch.disable", &Params::new())?;
        Ok(())
    }

    /// Starts writing screencast frames as `frame-00001.png`, ... into `directory`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the directory cannot be created, and the errors of
    /// [`Page::call`].
    pub fn start_recording(
        &mut self,
        directory: &Path,
        options: RecordingOptions,
    ) -> Result<(), Error> {
        self.recorder = Some(Recorder::begin(directory, options.max_frames)?);
        let mut params = Params::new()
            .string("format", "png")
            .int("everyNthFrame", i64::from(options.every_nth_frame.max(1)));
        if options.max_width > 0 && options.max_height > 0 {
            params = params
                .int("maxWidth", i64::from(options.max_width))
                .int("maxHeight", i64::from(options.max_height));
        }
        self.call("Page.startScreencast", &params)?;
        Ok(())
    }

    /// Stops the screencast and returns what was recorded, or `None` when nothing was.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the frame index cannot be written, and the errors of
    /// [`Page::call`].
    pub fn stop_recording(&mut self) -> Result<Option<Recording>, Error> {
        if self.recorder.is_none() {
            return Ok(None);
        }
        self.call("Page.stopScreencast", &Params::new())?;
        self.recorder.take().map(Recorder::end).transpose()
    }

    /// Console messages and browser log entries, in arrival order.
    pub fn console_messages(&self) -> &[ConsoleMessage] {
        &self.observations.console
    }

    /// Uncaught exceptions and unhandled rejections.
    pub fn exceptions(&self) -> &[Exception] {
        &self.observations.exceptions
    }

    /// Failed requests.
    pub fn network_failures(&self) -> &[NetworkFailure] {
        &self.observations.network_failures
    }

    /// Responses to document requests, with their status codes.
    pub fn document_responses(&self) -> &[DocumentResponse] {
        &self.observations.documents
    }

    /// Calls of bindings installed with [`Page::add_binding`].
    pub fn binding_calls(&self) -> &[BindingCall] {
        &self.observations.bindings
    }

    /// The number of load events of the main frame so far.
    pub fn load_count(&self) -> u64 {
        self.observations.load_count
    }

    /// The number of records (and queued events) dropped because a bound was reached.
    pub fn dropped_count(&self) -> u64 {
        self.observations.dropped + self.browser.connection.dropped_event_count()
    }

    /// Forgets the console messages, exceptions, failures, responses and binding calls
    /// collected so far.
    pub fn clear_observations(&mut self) {
        self.observations.clear();
    }

    /// Processes events until `condition` holds or `timeout` passes.
    fn wait_until(
        &mut self,
        what: &str,
        timeout: Duration,
        condition: impl Fn(&Observations) -> bool,
    ) -> Result<(), Error> {
        let started = Instant::now();
        let deadline = started + timeout;
        while !condition(&self.observations) {
            let Some(event) = self.browser.connection.next_event(deadline)? else {
                let what = what.to_owned();
                return Err(Error::Timeout { what, waited: started.elapsed(), last_error: None });
            };
            self.handle(&event)?;
        }
        Ok(())
    }

    /// Processes queued events and those that arrive before `deadline`.
    fn process_events_until(&mut self, deadline: Instant) -> Result<(), Error> {
        while let Some(event) = self.browser.connection.next_event(deadline)? {
            self.handle(&event)?;
        }
        Ok(())
    }

    fn handle(&mut self, event: &Message) -> Result<(), Error> {
        let MessageKind::Event(method) = event.kind() else { return Ok(()) };
        let own = event.session_id() == Some(self.session_id.as_str());
        if !own && !self.is_worker_session(event.session_id()) {
            return Ok(());
        }
        let body = event.body()?;
        let params = field(&body, &["params"]).unwrap_or(&Value::Null);
        match method {
            "Page.screencastFrame" if own => self.record_frame(params),
            "Inspector.detached" | "Inspector.targetCrashed" if own => Err(Error::Closed),
            "Target.attachedToTarget" if own => self.attach_child(params),
            "Target.detachedFromTarget" if own => {
                self.detach_child(params);
                Ok(())
            }
            // A worker's console messages and exceptions count as the page's.
            _ => {
                self.observations.record(method, params);
                Ok(())
            }
        }
    }

    /// Saves a screencast frame. The connection acknowledged it on arrival.
    fn record_frame(&mut self, params: &Value<'_>) -> Result<(), Error> {
        let Some(recorder) = self.recorder.as_mut() else { return Ok(()) };
        let timestamp = field(params, &["metadata", "timestamp"])
            .and_then(Value::as_number)
            .and_then(|n| n.as_f64().ok())
            .unwrap_or(0.0);
        recorder.write_frame(string_at(params, &["data"]), timestamp)
    }
}

impl Drop for Page<'_> {
    fn drop(&mut self) {
        if let Some(recorder) = self.recorder.take() {
            let _ = self.browser.connection.send(
                Some(&self.session_id),
                "Page.stopScreencast",
                &Params::new(),
            );
            let _ = recorder.end();
        }
        let params = Params::new().string("targetId", &self.target_id);
        let _ = self.browser.connection.send(None, "Target.closeTarget", &params);
    }
}

/// `text` as a JavaScript string literal (JSON strings are valid JavaScript).
fn js_string(text: &str) -> String {
    let mut literal = String::with_capacity(text.len() + 2);
    // Writing into a String cannot fail.
    let _ = sibuna_json::write_string(&mut literal, text);
    literal
}
