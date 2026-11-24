//! Expand the evaluated value into an ordinary JSON document with bounded work and space.

use std::fmt::{self, Write};
use std::io;

use jlv_lang::Value;
use sibuna_lb::Config;

use crate::invalid;

struct Document {
    json: String,
    values: usize,
}

impl Write for Document {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > Config::DOCUMENT_LIMITS.max_input_bytes - self.json.len() {
            return Err(fmt::Error);
        }
        self.json.push_str(text);
        Ok(())
    }
}

pub(super) fn encode(value: &Value) -> io::Result<String> {
    let mut document = Document { json: String::new(), values: 0 };
    document.value(value, 0)?;
    Ok(document.json)
}

fn full(_: fmt::Error) -> io::Error {
    invalid("evaluated edge document exceeds the byte limit")
}

impl Document {
    fn value(&mut self, value: &Value, depth: usize) -> io::Result<()> {
        self.values += 1;
        if self.values > Config::DOCUMENT_LIMITS.max_values
            || depth > Config::DOCUMENT_LIMITS.max_depth
        {
            return Err(invalid("evaluated edge document exceeds its value or nesting limit"));
        }
        match value {
            Value::Null => self.write_str("null"),
            Value::Bool(b) => write!(self, "{b}"),
            Value::Int(i) => write!(self, "{i}"),
            Value::Text(s) => sibuna_json::write_string(self, s),
            Value::List(items) => {
                self.write_char('[').map_err(full)?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        self.write_char(',').map_err(full)?;
                    }
                    self.value(item, depth + 1)?;
                }
                self.write_char(']')
            }
            Value::Map(items) => {
                self.write_char('{').map_err(full)?;
                for (index, (key, item)) in items.iter().enumerate() {
                    if index > 0 {
                        self.write_char(',').map_err(full)?;
                    }
                    sibuna_json::write_string(self, key).map_err(full)?;
                    self.write_char(':').map_err(full)?;
                    self.value(item, depth + 1)?;
                }
                self.write_char('}')
            }
            Value::Bytes(_) | Value::Opaque(_) => {
                return Err(invalid("edge document contains a non-JSON value"));
            }
        }
        .map_err(full)
    }
}
