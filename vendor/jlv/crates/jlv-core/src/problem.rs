//! The structured diagnostic every jlavideploy surface renders.
//!
//! A [`Problem`] carries the same facts to every audience: people read it as an Elm-style
//! report ([`Problem::render_text`]); programs and agents read its JSON form
//! ([`Problem::to_json`]), which also serves as an RFC 9457 problem body. JDD 0003
//! requires code, title, explanation, source span, related spans, retry class and next
//! action, so that no client has to scrape English text to automate recovery.

use std::fmt;

use gd_json::Object;
use gd_report::{Report, Style};

use crate::Value;

/// A machine-applicable repair for agents.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Call this operation with this input.
    Op {
        /// The operation name, such as `change.list`.
        op: String,
        /// The input object.
        input: Value,
    },
    /// Run this command line, given as an argument vector.
    Argv(Vec<String>),
}

/// Where in a source text a problem lies.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Location {
    /// The file name as it should be shown.
    pub path: String,
    /// 1-based line; 0 when unknown.
    pub line: usize,
    /// 1-based column counting Unicode scalars; 0 when unknown.
    pub column: usize,
    /// The source line, for an excerpt.
    pub text: String,
    /// The underlined byte range within `text`.
    pub span: (usize, usize),
}

/// What a caller may do about a problem without asking a person (JDD 0003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetryClass {
    /// Retrying the same request cannot succeed; the input or authority must change.
    #[default]
    None,
    /// The same request may succeed later, such as after a transport failure.
    Retry,
    /// Fresh observations are needed before a new attempt.
    Refresh,
    /// The plan no longer fits current state; a new plan is needed.
    Replan,
    /// A person must decide, such as after an indeterminate effect.
    Manual,
}

impl RetryClass {
    /// The lower-case name used in JSON.
    pub fn name(self) -> &'static str {
        match self {
            RetryClass::None => "none",
            RetryClass::Retry => "retry",
            RetryClass::Refresh => "refresh",
            RetryClass::Replan => "replan",
            RetryClass::Manual => "manual",
        }
    }

    /// The class named `name`; an unknown name reads as [`RetryClass::None`].
    pub fn from_name(name: &str) -> RetryClass {
        match name {
            "retry" => RetryClass::Retry,
            "refresh" => RetryClass::Refresh,
            "replan" => RetryClass::Replan,
            "manual" => RetryClass::Manual,
            _ => RetryClass::None,
        }
    }
}

impl Location {
    /// The position of bytes `start..end` of `source`, in file `path`.
    pub fn of(path: &str, source: &str, start: usize, end: usize) -> Location {
        let report = Report::default().at(path, source, start, end);
        let (text, span) = report.excerpt.map(|e| (e.text, (e.start, e.end))).unwrap_or_default();
        Location { path: path.to_string(), line: report.line, column: report.column, text, span }
    }
}

/// A failed operation, described for people and for programs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Problem {
    /// A stable code such as `type_mismatch` or `jlv.plan.stale`.
    pub code: String,
    /// A short upper-case title such as `STALE TARGET`.
    pub title: String,
    /// What happened, in plain sentences.
    pub message: String,
    /// What did not happen because of it, such as "The target did not move."
    pub consequence: String,
    /// How to fix it, in prose; the first is the `Hint:`.
    pub hints: Vec<String>,
    /// How to fix it, as operations or command lines.
    pub actions: Vec<Action>,
    /// The HTTP status that best describes it.
    pub status: u16,
    /// The resource the problem concerns, shown in the title rule; may be empty.
    pub context: String,
    /// The source position, when the problem refers to source text.
    pub location: Option<Location>,
    /// Other source positions that explain the problem, such as a first definition.
    pub related: Vec<Location>,
    /// What a caller may do without a person.
    pub retry_class: RetryClass,
    /// When a retry may succeed, in milliseconds from now, for limits that clear by
    /// themselves.
    pub retry_after_ms: Option<u64>,
}

impl Problem {
    /// Starts a problem with status 400; add facts with the chaining methods.
    pub fn new(code: &str, title: &str, message: &str) -> Problem {
        Problem {
            code: code.to_string(),
            title: title.to_string(),
            message: message.to_string(),
            status: 400,
            ..Problem::default()
        }
    }

    /// Sets when a retry may succeed, in milliseconds.
    pub fn retry_after(mut self, ms: u64) -> Problem {
        self.retry_after_ms = Some(ms);
        self
    }

    /// Sets the retry class.
    pub fn retry_class(mut self, class: RetryClass) -> Problem {
        self.retry_class = class;
        self
    }

    /// Adds a related source position, such as where a name was first defined.
    pub fn related(mut self, path: &str, source: &str, start: usize, end: usize) -> Problem {
        self.related.push(Location::of(path, source, start, end));
        self
    }

    /// Sets the HTTP status.
    pub fn status(mut self, status: u16) -> Problem {
        self.status = status;
        self
    }

    /// Sets the consequence sentence.
    pub fn consequence(mut self, text: &str) -> Problem {
        self.consequence = text.to_string();
        self
    }

    /// Adds a hint.
    pub fn hint(mut self, text: &str) -> Problem {
        self.hints.push(text.to_string());
        self
    }

    /// Adds an operation an agent may call to repair the problem.
    pub fn action_op(mut self, op: &str, input: Value) -> Problem {
        self.actions.push(Action::Op { op: op.to_string(), input });
        self
    }

    /// Adds a command line that repairs the problem.
    pub fn action_argv(mut self, argv: &[&str]) -> Problem {
        self.actions.push(Action::Argv(argv.iter().map(|a| a.to_string()).collect()));
        self
    }

    /// Names the resource the problem concerns.
    pub fn context(mut self, text: &str) -> Problem {
        self.context = text.to_string();
        self
    }

    /// Positions the problem at bytes `start..end` of `source`, in file `path`.
    pub fn at(mut self, path: &str, source: &str, start: usize, end: usize) -> Problem {
        self.location = Some(Location::of(path, source, start, end));
        self
    }

    /// A resource that does not exist or that the caller may not see. Both cases read
    /// the same, so the reply never reveals a hidden resource.
    pub fn not_found(what: &str, name: &str) -> Problem {
        let code = format!("jlv.{what}.not-found");
        Problem::new(&code, "NOT FOUND", &format!("No {what} `{name}` is visible to you."))
            .consequence("Nothing was read or changed.")
            .status(404)
            .hint("Check the name, or ask a maintainer for access.")
    }

    /// An input member that fails validation. Its hint, [`Problem::INPUT_HINT`], says to
    /// correct the member; an operation replaces it with one that names the operation.
    pub fn invalid_input(field: &str, reason: &str) -> Problem {
        Problem::new("jlv.input.invalid", "INVALID INPUT", &format!("`{field}` {reason}."))
            .consequence("Nothing was changed.")
            .status(422)
            .context(field)
            .hint(Problem::INPUT_HINT)
    }

    /// The hint of [`Problem::invalid_input`] until an operation names itself.
    pub const INPUT_HINT: &str = "Correct the member the message names, then try again.";

    /// A request without valid credentials.
    pub fn unauthenticated() -> Problem {
        Problem::new(
            "jlv.auth.unauthenticated",
            "SIGN-IN REQUIRED",
            "This request has no valid credentials.",
        )
        .consequence("Nothing was read or changed.")
        .status(401)
        .hint("Send a token as `Authorization: Bearer <token>`, or sign in again.")
        .hint("An administrator creates a token with `jlvdadm token create`.")
        .action_argv(&["jlvd", "auth", "login", "--url", "<url>"])
    }

    /// An authenticated principal that lacks the grant for an operation on a visible
    /// resource.
    pub fn forbidden(op: &str, resource: &str) -> Problem {
        Problem::new(
            "jlv.auth.forbidden",
            "NOT ALLOWED",
            &format!("You may see {resource}, but you have no grant for `{op}` there."),
        )
        .consequence("Nothing was changed.")
        .status(403)
        .hint("Ask a maintainer of the resource for the grant.")
        .context(resource)
    }

    /// A mutable resource whose generation moved since the caller read it.
    pub fn stale(resource: &str, expected: i64, actual: i64) -> Problem {
        Problem::new(
            "jlv.generation.stale",
            "STALE GENERATION",
            &format!("{resource} is at generation {actual}, but the request expected {expected}."),
        )
        .consequence("Nothing was changed.")
        .status(409)
        .hint("Read the resource again and repeat the request with the current generation.")
        .context(resource)
    }

    /// A failure inside the server. The detail goes to the server log, not to the caller.
    pub fn internal() -> Problem {
        let message = "The server could not complete this request.";
        Problem::new("jlv.internal", "INTERNAL ERROR", message)
            .consequence("The request may not have taken effect.")
            .status(500)
            .hint("Retry with the same idempotency key.")
            .hint("If it fails again, tell the platform administrator.")
    }

    /// The JSON form. `type` and `detail` make it an RFC 9457 problem body.
    pub fn to_json(&self) -> Value {
        let mut o = Object::new();
        let s = |v: &str| Value::String(v.to_string());
        o.insert("type".into(), s(&format!("urn:jlv:problem:{}", self.code)));
        o.insert("code".into(), s(&self.code));
        o.insert("title".into(), s(&self.title));
        o.insert("status".into(), Value::from(self.status));
        o.insert("message".into(), s(&self.message));
        o.insert("detail".into(), s(&self.message));
        if !self.consequence.is_empty() {
            o.insert("consequence".into(), s(&self.consequence));
        }
        o.insert("hints".into(), Value::Array(self.hints.iter().map(|h| s(h)).collect()));
        o.insert("actions".into(), Value::Array(self.actions.iter().map(action_json).collect()));
        if !self.context.is_empty() {
            o.insert("context".into(), s(&self.context));
        }
        o.insert("location".into(), self.location.as_ref().map_or(Value::Null, location_json));
        let related = self.related.iter().map(location_json).collect();
        o.insert("related".into(), Value::Array(related));
        o.insert("retry_class".into(), s(self.retry_class.name()));
        if let Some(ms) = self.retry_after_ms {
            o.insert("retry_after_ms".into(), Value::from(ms));
        }
        Value::Object(o)
    }

    /// Reads the JSON form; `None` when `value` lacks a code, title or message.
    pub fn from_json(value: &Value) -> Option<Problem> {
        let text = |k: &str| value.get(k).and_then(Value::as_str).map(str::to_string);
        let strings = |k: &str| -> Vec<String> {
            let items = value.get(k).and_then(Value::as_array);
            items
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        let actions = value.get("actions").and_then(Value::as_array);
        let actions = actions.map(|a| a.iter().filter_map(action_from_json).collect());
        Some(Problem {
            code: text("code")?,
            title: text("title")?,
            message: text("message")?,
            consequence: text("consequence").unwrap_or_default(),
            hints: strings("hints"),
            actions: actions.unwrap_or_default(),
            status: value
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok())
                .unwrap_or(400),
            context: text("context").unwrap_or_default(),
            location: value.get("location").and_then(location_from_json),
            related: value
                .get("related")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(location_from_json).collect())
                .unwrap_or_default(),
            retry_class: RetryClass::from_name(&text("retry_class").unwrap_or_default()),
            retry_after_ms: value.get("retry_after_ms").and_then(Value::as_u64),
        })
    }

    /// The Elm-style report for terminals.
    pub fn report(&self) -> Report {
        let mut message = self.message.clone();
        if !self.consequence.is_empty() {
            message.push('\n');
            message.push_str(&self.consequence);
        }
        for rel in &self.related {
            if rel.line > 0 {
                message.push_str(&format!("\nSee also {}:{}:{}.", rel.path, rel.line, rel.column));
            } else if !rel.path.is_empty() {
                message.push_str(&format!("\nSee also {}.", rel.path));
            }
        }
        let mut report = Report::error(&self.code, &self.title, &message);
        report.hints = self.hints.clone();
        report.path = self.context.clone();
        if let Some(loc) = &self.location {
            report.path = loc.path.clone();
            report.line = loc.line;
            report.column = loc.column;
            let (start, end) = loc.span;
            report.excerpt = Some(gd_report::Excerpt {
                text: loc.text.clone(),
                start,
                end,
                before: String::new(),
            });
        }
        report
    }

    /// The report as terminal text, `width` cells wide, with ANSI color when `color`.
    pub fn render_text(&self, color: bool, width: usize) -> String {
        gd_report::render_text(&self.report(), &Style { color, width })
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.title, self.message)
    }
}

impl std::error::Error for Problem {}

fn action_json(action: &Action) -> Value {
    let mut o = Object::new();
    match action {
        Action::Op { op, input } => {
            o.insert("op".into(), Value::String(op.clone()));
            o.insert("input".into(), input.clone());
        }
        Action::Argv(argv) => {
            let argv = argv.iter().map(|a| Value::String(a.clone())).collect();
            o.insert("argv".into(), Value::Array(argv));
        }
    }
    Value::Object(o)
}

fn action_from_json(value: &Value) -> Option<Action> {
    if let Some(op) = value.get("op").and_then(Value::as_str) {
        let input = value.get("input").cloned().unwrap_or(Value::Object(Object::new()));
        return Some(Action::Op { op: op.to_string(), input });
    }
    let argv = value.get("argv")?.as_array()?;
    Some(Action::Argv(argv.iter().filter_map(|a| a.as_str().map(str::to_string)).collect()))
}

fn location_json(loc: &Location) -> Value {
    let mut o = Object::new();
    o.insert("path".into(), Value::String(loc.path.clone()));
    o.insert("line".into(), Value::from(loc.line));
    o.insert("column".into(), Value::from(loc.column));
    o.insert("text".into(), Value::String(loc.text.clone()));
    o.insert("span".into(), Value::Array(vec![Value::from(loc.span.0), Value::from(loc.span.1)]));
    Value::Object(o)
}

fn location_from_json(value: &Value) -> Option<Location> {
    let n = |k: &str| value.get(k).and_then(Value::as_u64).unwrap_or(0) as usize;
    let span = value.get("span").and_then(Value::as_array);
    let at = |i: usize| span.and_then(|s| s.get(i)).and_then(Value::as_u64).unwrap_or(0) as usize;
    Some(Location {
        path: value.get("path")?.as_str()?.to_string(),
        line: n("line"),
        column: n("column"),
        text: value.get("text").and_then(Value::as_str).unwrap_or("").to_string(),
        span: (at(0), at(1)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_with_actions_and_location() {
        let p = Problem::not_found("stack", "lab/site/prod")
            .action_op("stack.list", gd_json::parse(r#"{"project":"lab/site"}"#).unwrap())
            .action_argv(&["jlvd", "stack", "list"])
            .retry_class(RetryClass::Refresh)
            .at("deploy.jlv", "one\nkxzy two\n", 4, 8)
            .related("deploy.jlv", "one\nkxzy two\n", 0, 3);
        let json = p.to_json();
        assert_eq!(json["type"], "urn:jlv:problem:jlv.stack.not-found");
        assert_eq!(json["status"], 404);
        assert_eq!(Problem::from_json(&json).unwrap(), p);
    }

    #[test]
    fn renders_an_elm_style_report() {
        let text = Problem::stale("lab/site/prod", 4, 5)
            .related("deploy.jlv", "let x = 1;\n", 0, 3)
            .render_text(false, 80);
        assert!(text.starts_with("-- STALE GENERATION [jlv.generation.stale] --"));
        assert!(text.contains("lab/site/prod"));
        assert!(text.contains("Nothing was changed."));
        assert!(text.contains("See also deploy.jlv:1:1."));
        assert!(text.contains("Hint: Read the resource again"));
        let bad_status =
            gd_json::parse(r#"{"code":"x","title":"X","message":"m","status":70000}"#).unwrap();
        assert_eq!(Problem::from_json(&bad_status).unwrap().status, 400);
    }
}
