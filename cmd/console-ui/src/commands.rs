//! The command list the module hands back to the browser bridge after each event.
//!
//! `glue.js` reads one JSON array of command objects after every call and executes them in
//! order: `request` (fetch, then post the reply back as a response event), `download`,
//! `copy`, `save-text`, `geometry`, `timer`, `connect`, `send`, `disconnect`, `focus`,
//! `history` and `appearance`. Member order and spelling are part of the bridge contract
//! and match the Zig module byte for byte.

use std::fmt;

use sibuna_console_protocol::codec::Encode;
use sibuna_json::Writer;

use crate::error::UiError;
use crate::wipe::wipe_string;

/// The JSON writer a command body is written with.
pub type Json<'a> = Writer<&'a mut String>;

/// A scalar member of a flat command object (the Rust form of Zig's `json_fields`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Field<'a> {
    /// A string, escaped as JSON.
    Text(&'a str),
    /// An unsigned number, written as a plain JSON number.
    Unsigned(u64),
    /// A signed number.
    Signed(i64),
    /// `true` or `false`.
    Bool(bool),
    /// `null`, for an absent optional value.
    Null,
}

impl Field<'_> {
    fn write(self, json: &mut Json<'_>) -> fmt::Result {
        match self {
            Field::Text(text) => json.string(text),
            Field::Unsigned(number) => json.uint(number),
            Field::Signed(number) => json.int(number),
            Field::Bool(flag) => json.bool(flag),
            Field::Null => json.null(),
        }
    }
}

/// Writes a flat object of `fields`, in order, as one JSON value.
///
/// # Errors
///
/// Returns the sink's error.
pub fn write_fields(json: &mut Json<'_>, fields: &[(&str, Field<'_>)]) -> fmt::Result {
    json.begin_object()?;
    for (name, value) in fields {
        json.key(name)?;
        value.write(json)?;
    }
    json.end_object()
}

/// The commands of one event, as the JSON array text the bridge reads.
///
/// The buffer is owned and reused: [`Commands::begin`] erases the previous list, so a
/// request body that carried a password does not outlive the event that sent it. Its size
/// needs no separate bound: every command is a function of the bounded event input and the
/// bounded state.
#[derive(Debug, Default)]
pub struct Commands {
    text: String,
    count: usize,
}

impl Commands {
    /// Erases the previous list and opens a new one.
    pub fn begin(&mut self) {
        wipe_string(&mut self.text);
        self.text.push('[');
        self.count = 0;
    }

    /// Closes the list opened by [`Commands::begin`].
    pub fn end(&mut self) {
        self.text.push(']');
    }

    /// Returns the list text: a JSON array once [`Commands::end`] has run.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the number of commands written since [`Commands::begin`].
    pub fn count(&self) -> usize {
        self.count
    }

    /// Appends one command that `write` writes as a single JSON value. The writer is a
    /// trait object, so the many call sites share one copy of this function in the module.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if `write` fails; the partial command is removed.
    pub fn emit(
        &mut self,
        write: &mut dyn FnMut(&mut Json<'_>) -> fmt::Result,
    ) -> Result<(), UiError> {
        let start = self.text.len();
        if self.count > 0 {
            self.text.push(',');
        }
        let mut json = Writer::new(&mut self.text);
        if write(&mut json).is_err() {
            self.text.truncate(start);
            return Err(UiError::Write);
        }
        self.count += 1;
        Ok(())
    }

    /// Appends a flat command object.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn emit_fields(&mut self, fields: &[(&str, Field<'_>)]) -> Result<(), UiError> {
        self.emit(&mut |json| write_fields(json, fields))
    }

    /// Asks the bridge to `GET` `path` and to reply with a response event named `id`.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn get(&mut self, id: &str, path: &str) -> Result<(), UiError> {
        self.emit_fields(&[
            ("op", Field::Text("request")),
            ("id", Field::Text(id)),
            ("method", Field::Text("GET")),
            ("path", Field::Text(path)),
        ])
    }

    /// Asks the bridge to `POST` the JSON value `body` writes to `path`, with the session's
    /// `csrf` token, and to reply with a response event named `id`.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn post(
        &mut self,
        id: &str,
        path: &str,
        csrf: &str,
        body: &mut dyn FnMut(&mut Json<'_>) -> fmt::Result,
    ) -> Result<(), UiError> {
        self.emit(&mut |json| {
            json.begin_object()?;
            let envelope = [("op", "request"), ("method", "POST"), ("id", id), ("path", path)];
            for (name, value) in envelope {
                json.key(name)?;
                json.string(value)?;
            }
            json.key("csrf")?;
            json.string(csrf)?;
            json.key("body")?;
            body(json)?;
            json.end_object()
        })
    }

    /// Posts an encodable wire value; see [`Commands::post`].
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn post_value<T: Encode + ?Sized>(
        &mut self,
        id: &str,
        path: &str,
        csrf: &str,
        body: &T,
    ) -> Result<(), UiError> {
        self.post(id, path, csrf, &mut |json| body.encode(json))
    }

    /// Moves keyboard focus to the first element matching `selector` and scrolls it into
    /// view.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn focus(&mut self, selector: &str) -> Result<(), UiError> {
        self.emit_fields(&[("op", Field::Text("focus")), ("selector", Field::Text(selector))])
    }

    /// Moves keyboard focus to `selector` and scrolls the window to the top, as after a
    /// change of page.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn focus_top(&mut self, selector: &str) -> Result<(), UiError> {
        self.emit_fields(&[
            ("op", Field::Text("focus")),
            ("selector", Field::Text(selector)),
            ("top", Field::Bool(true)),
        ])
    }

    /// Starts (or restarts) the browser timer `id`; it fires a timer event after
    /// `delay_ms` milliseconds.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn timer(&mut self, id: &str, delay_ms: u64) -> Result<(), UiError> {
        self.emit_fields(&[
            ("op", Field::Text("timer")),
            ("id", Field::Text(id)),
            ("delay_ms", Field::Unsigned(delay_ms)),
        ])
    }

    /// Opens the WebSocket at `path`, closing any previous one.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn connect(&mut self, path: &str) -> Result<(), UiError> {
        self.emit_fields(&[("op", Field::Text("connect")), ("path", Field::Text(path))])
    }

    /// Closes the WebSocket, aborts the geometry download and cancels every timer.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn disconnect(&mut self) -> Result<(), UiError> {
        self.emit_fields(&[("op", Field::Text("disconnect"))])
    }

    /// Downloads the geometry asset at `path` into the module's geometry buffer.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn geometry(&mut self, path: &str) -> Result<(), UiError> {
        self.emit_fields(&[("op", Field::Text("geometry")), ("path", Field::Text(path))])
    }

    /// Copies `text` to the clipboard; the bridge replies with a response event named `id`
    /// whose status is 200 on success and 0 on failure.
    ///
    /// # Errors
    ///
    /// As [`Commands::emit`].
    pub fn copy(&mut self, id: &str, text: &str) -> Result<(), UiError> {
        self.emit_fields(&[
            ("op", Field::Text("copy")),
            ("id", Field::Text(id)),
            ("text", Field::Text(text)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_form_one_json_array_in_the_zig_member_order() {
        let mut commands = Commands::default();
        commands.begin();
        commands.get("session", "/console/api/session").unwrap();
        commands
            .post("login", "/console/api/login", "token", &mut |json| {
                write_fields(json, &[("username", Field::Text("a\"b")), ("n", Field::Null)])
            })
            .unwrap();
        commands.focus_top("main h1").unwrap();
        commands.timer("age", 1000).unwrap();
        commands.end();
        assert_eq!(
            commands.as_str(),
            "[{\"op\":\"request\",\"id\":\"session\",\"method\":\"GET\",\
             \"path\":\"/console/api/session\"},\
             {\"op\":\"request\",\"method\":\"POST\",\"id\":\"login\",\
             \"path\":\"/console/api/login\",\"csrf\":\"token\",\
             \"body\":{\"username\":\"a\\\"b\",\"n\":null}},\
             {\"op\":\"focus\",\"selector\":\"main h1\",\"top\":true},\
             {\"op\":\"timer\",\"id\":\"age\",\"delay_ms\":1000}]"
        );
        assert_eq!(commands.count(), 4);
        commands.begin();
        commands.end();
        assert_eq!(commands.as_str(), "[]");
    }

    #[test]
    fn a_failed_command_leaves_no_partial_text() {
        let mut commands = Commands::default();
        commands.begin();
        commands.disconnect().unwrap();
        assert_eq!(commands.emit(&mut |_| Err(fmt::Error)), Err(UiError::Write));
        commands.end();
        assert_eq!(commands.as_str(), "[{\"op\":\"disconnect\"}]");
    }

    /// Ported from `json_fields.zig`: escaping, extremes, null and booleans match the
    /// standard JSON writer.
    #[test]
    fn flat_fields_encode_like_the_standard_writer() {
        let mut text = String::new();
        let mut json = Writer::new(&mut text);
        write_fields(
            &mut json,
            &[
                ("text", Field::Text("\"\\\n\u{4e16}\u{754c}")),
                ("minimum", Field::Signed(i64::MIN)),
                ("maximum", Field::Unsigned(u64::MAX)),
                ("optional", Field::Null),
                ("present", Field::Text("<script>")),
                ("flag", Field::Bool(true)),
                ("role", Field::Text("viewer")),
            ],
        )
        .unwrap();
        assert_eq!(
            text,
            "{\"text\":\"\\\"\\\\\\n\u{4e16}\u{754c}\",\"minimum\":-9223372036854775808,\
             \"maximum\":18446744073709551615,\"optional\":null,\"present\":\"<script>\",\
             \"flag\":true,\"role\":\"viewer\"}"
        );
    }
}
