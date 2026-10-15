//! What a page reports through events: console output, exceptions, network failures,
//! document responses, binding calls and load events.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use sibuna_json::Value;

use crate::cdp::{field, string_at};

/// The most records of each kind a page keeps; later ones are counted and dropped.
const MAX_RECORDS: usize = 10_000;

/// One console message or browser log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleMessage {
    /// `console-api` for `console.*` calls; otherwise the log entry's source, such as
    /// `network`, `javascript` or `security`.
    pub source: String,
    /// `log`, `info`, `debug`, `warning`, `error`, `assert` and the other `console.*`
    /// types, or a log entry's level (`verbose`, `info`, `warning`, `error`).
    pub level: String,
    /// The message text; a `console.*` call's arguments joined by spaces.
    pub text: String,
    /// The resource the entry concerns, when the browser names one.
    pub url: String,
}

impl ConsoleMessage {
    /// True for `console.error`, failed `console.assert` and error-level log entries.
    pub fn is_error(&self) -> bool {
        matches!(self.level.as_str(), "error" | "assert")
    }
}

/// An uncaught JavaScript exception or unhandled promise rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exception {
    /// The exception's description (usually with its stack), or the browser's summary.
    pub text: String,
    /// The script's URL, when known.
    pub url: String,
    /// The zero-based line in that script.
    pub line: i64,
}

/// A request that failed: refused, reset, blocked or cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFailure {
    /// The request's URL, or empty when the request began before observation did.
    pub url: String,
    /// Chromium's error name, such as `net::ERR_CONNECTION_REFUSED`.
    pub error_text: String,
    /// True when the page or a navigation cancelled the request.
    pub canceled: bool,
}

/// The response to a document request (a navigation or a frame).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentResponse {
    /// The document's URL.
    pub url: String,
    /// The HTTP status code.
    pub status: u16,
}

/// A call of a function installed with `Page::add_binding`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingCall {
    /// The binding's name.
    pub name: String,
    /// The string the page passed.
    pub payload: String,
    /// When the event was processed.
    pub at: Instant,
}

/// A request held by `Page::hold_requests`, waiting for `Page::release_request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRequest {
    /// The DevTools id that releases it.
    pub id: String,
    /// The request's URL.
    pub url: String,
    /// The request's method, such as `POST`.
    pub method: String,
}

/// Everything a page has reported since it was opened or last cleared.
#[derive(Debug, Default)]
pub(crate) struct Observations {
    pub(crate) console: Vec<ConsoleMessage>,
    pub(crate) exceptions: Vec<Exception>,
    pub(crate) network_failures: Vec<NetworkFailure>,
    pub(crate) documents: Vec<DocumentResponse>,
    pub(crate) bindings: Vec<BindingCall>,
    /// Held requests not yet taken by `Page::wait_for_held_request`.
    pub(crate) held: VecDeque<HeldRequest>,
    pub(crate) load_count: u64,
    pub(crate) dropped: u64,
    /// The URLs of requests in flight, by request id, to name the URL of a failure.
    requests: HashMap<String, String>,
}

impl Observations {
    /// Records the event `method` with its `params`. Unknown events are ignored.
    pub(crate) fn record(&mut self, method: &str, params: &Value<'_>) {
        match method {
            "Runtime.consoleAPICalled" => {
                let message = ConsoleMessage {
                    source: "console-api".into(),
                    level: string_at(params, &["type"]).to_owned(),
                    text: console_text(params),
                    url: String::new(),
                };
                push(&mut self.console, message, &mut self.dropped);
            }
            "Log.entryAdded" => {
                let message = ConsoleMessage {
                    source: string_at(params, &["entry", "source"]).to_owned(),
                    level: string_at(params, &["entry", "level"]).to_owned(),
                    text: string_at(params, &["entry", "text"]).to_owned(),
                    url: string_at(params, &["entry", "url"]).to_owned(),
                };
                push(&mut self.console, message, &mut self.dropped);
            }
            "Runtime.exceptionThrown" => {
                let exception = exception(field(params, &["exceptionDetails"]));
                push(&mut self.exceptions, exception, &mut self.dropped);
            }
            "Page.loadEventFired" => self.load_count += 1,
            "Fetch.requestPaused" if self.held.len() < MAX_RECORDS => {
                self.held.push_back(HeldRequest {
                    id: string_at(params, &["requestId"]).to_owned(),
                    url: string_at(params, &["request", "url"]).to_owned(),
                    method: string_at(params, &["request", "method"]).to_owned(),
                });
            }
            "Runtime.bindingCalled" => {
                let call = BindingCall {
                    name: string_at(params, &["name"]).to_owned(),
                    payload: string_at(params, &["payload"]).to_owned(),
                    at: Instant::now(),
                };
                push(&mut self.bindings, call, &mut self.dropped);
            }
            _ => self.record_network(method, params),
        }
    }

    fn record_network(&mut self, method: &str, params: &Value<'_>) {
        let request_id = string_at(params, &["requestId"]);
        match method {
            "Network.requestWillBeSent" if self.requests.len() < MAX_RECORDS => {
                let url = string_at(params, &["request", "url"]).to_owned();
                self.requests.insert(request_id.to_owned(), url);
            }
            "Network.responseReceived" if string_at(params, &["type"]) == "Document" => {
                let status = field(params, &["response", "status"])
                    .and_then(Value::as_number)
                    .and_then(|number| number.as_f64().ok())
                    .map_or(0, |status| status.clamp(0.0, 999.0) as u16);
                let url = string_at(params, &["response", "url"]).to_owned();
                push(&mut self.documents, DocumentResponse { url, status }, &mut self.dropped);
            }
            "Network.loadingFinished" => {
                self.requests.remove(request_id);
            }
            "Network.loadingFailed" => {
                let failure = NetworkFailure {
                    url: self.requests.remove(request_id).unwrap_or_default(),
                    error_text: string_at(params, &["errorText"]).to_owned(),
                    canceled: field(params, &["canceled"]).and_then(Value::as_bool) == Some(true),
                };
                push(&mut self.network_failures, failure, &mut self.dropped);
            }
            _ => {}
        }
    }

    /// Forgets every record, keeping the load count.
    pub(crate) fn clear(&mut self) {
        self.console.clear();
        self.exceptions.clear();
        self.network_failures.clear();
        self.documents.clear();
        self.bindings.clear();
        self.dropped = 0;
    }
}

fn push<T>(records: &mut Vec<T>, record: T, dropped: &mut u64) {
    if records.len() < MAX_RECORDS {
        records.push(record);
    } else {
        *dropped += 1;
    }
}

/// The text of a `console.*` call: each argument's value, description or type, joined by
/// spaces, as DevTools shows it.
fn console_text(params: &Value<'_>) -> String {
    let arguments = field(params, &["args"]).and_then(Value::as_array).unwrap_or_default();
    let parts: Vec<String> = arguments.iter().map(remote_object_text).collect();
    parts.join(" ")
}

/// A short text for a `Runtime.RemoteObject`.
pub(crate) fn remote_object_text(object: &Value<'_>) -> String {
    match field(object, &["value"]) {
        Some(Value::String(text)) => text.to_string(),
        Some(value) => value.to_string(),
        None => {
            for key in ["unserializableValue", "description", "type"] {
                let text = string_at(object, &[key]);
                if !text.is_empty() {
                    return text.to_owned();
                }
            }
            String::new()
        }
    }
}

/// An [`Exception`] from `Runtime.ExceptionDetails`.
pub(crate) fn exception(details: Option<&Value<'_>>) -> Exception {
    let Some(details) = details else {
        return Exception {
            text: "an exception without details".into(),
            url: String::new(),
            line: 0,
        };
    };
    let description = string_at(details, &["exception", "description"]);
    let text = if description.is_empty() { string_at(details, &["text"]) } else { description };
    let line = field(details, &["lineNumber"])
        .and_then(Value::as_number)
        .and_then(|number| number.as_i64().ok())
        .unwrap_or(0);
    Exception { text: text.to_owned(), url: string_at(details, &["url"]).to_owned(), line }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(observations: &mut Observations, method: &str, params: &str) {
        let value = sibuna_json::parse(params.as_bytes()).unwrap();
        observations.record(method, &value);
    }

    #[test]
    fn records_console_calls_log_entries_and_exceptions() {
        let mut seen = Observations::default();
        record(
            &mut seen,
            "Runtime.consoleAPICalled",
            r#"{"type":"error","args":[
            {"type":"string","value":"bad"},{"type":"number","value":42},
            {"type":"number","unserializableValue":"NaN"},
            {"type":"object","description":"Object"}]}"#,
        );
        record(
            &mut seen,
            "Log.entryAdded",
            r#"{"entry":{"source":"network","level":"error",
            "text":"Failed to load resource","url":"http://a/x"}}"#,
        );
        record(
            &mut seen,
            "Runtime.exceptionThrown",
            r#"{"exceptionDetails":{"text":"Uncaught",
            "lineNumber":3,"url":"http://a/s.js",
            "exception":{"description":"TypeError: x is undefined\n    at s.js:4"}}}"#,
        );
        assert_eq!(seen.console[0].text, "bad 42 NaN Object");
        assert!(seen.console[0].is_error());
        assert_eq!(seen.console[1].source, "network");
        assert_eq!(seen.console[1].url, "http://a/x");
        assert!(seen.exceptions[0].text.starts_with("TypeError"));
        assert_eq!(
            (seen.exceptions[0].line, seen.exceptions[0].url.as_str()),
            (3, "http://a/s.js")
        );
    }

    #[test]
    fn names_the_url_of_a_failed_request() {
        let mut seen = Observations::default();
        record(
            &mut seen,
            "Network.requestWillBeSent",
            r#"{"requestId":"7","request":{"url":"http://a/f"}}"#,
        );
        record(
            &mut seen,
            "Network.requestWillBeSent",
            r#"{"requestId":"8","request":{"url":"http://a/g"}}"#,
        );
        record(&mut seen, "Network.loadingFinished", r#"{"requestId":"8"}"#);
        record(
            &mut seen,
            "Network.loadingFailed",
            r#"{"requestId":"7","errorText":"net::ERR_CONNECTION_REFUSED","canceled":false}"#,
        );
        record(
            &mut seen,
            "Network.responseReceived",
            r#"{"requestId":"9","type":"Document","response":{"url":"http://a/","status":401}}"#,
        );
        assert_eq!(
            seen.network_failures,
            vec![NetworkFailure {
                url: "http://a/f".into(),
                error_text: "net::ERR_CONNECTION_REFUSED".into(),
                canceled: false,
            }]
        );
        assert_eq!(
            seen.documents,
            vec![DocumentResponse { url: "http://a/".into(), status: 401 }]
        );
        assert!(seen.requests.is_empty());
    }

    #[test]
    fn counts_loads_and_bindings_and_bounds_records() {
        let mut seen = Observations::default();
        record(&mut seen, "Page.loadEventFired", r#"{"timestamp":1}"#);
        record(&mut seen, "Runtime.bindingCalled", r#"{"name":"report","payload":"hi"}"#);
        record(&mut seen, "Unknown.event", "{}");
        record(
            &mut seen,
            "Fetch.requestPaused",
            r#"{"requestId":"interception-1","request":{"url":"http://a/v","method":"POST"}}"#,
        );
        assert_eq!((seen.load_count, seen.bindings[0].payload.as_str()), (1, "hi"));
        assert_eq!(
            seen.held.pop_front().map(|held| (held.id, held.method)),
            Some(("interception-1".into(), "POST".into()))
        );
        for _ in 0..MAX_RECORDS + 5 {
            record(&mut seen, "Runtime.consoleAPICalled", r#"{"type":"log","args":[]}"#);
        }
        assert_eq!((seen.console.len(), seen.dropped), (MAX_RECORDS, 5));
        seen.clear();
        assert_eq!((seen.console.len(), seen.dropped, seen.load_count), (0, 0, 1));
    }
}
