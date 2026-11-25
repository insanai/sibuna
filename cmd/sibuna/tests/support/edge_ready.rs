//! Startup diagnostics may precede the edge readiness announcement.

use std::io::BufRead;

/// Waits for the serving process, returning its startup messages if it exits early.
pub fn wait(stderr: &mut impl BufRead) -> Result<(), String> {
    let mut messages = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if stderr.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err(messages);
        }
        if line.trim_end() == "Sibuna edge listeners ready" {
            return Ok(());
        }
        messages.push_str(&line);
    }
}
