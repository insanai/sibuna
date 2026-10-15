//! `sibuna-browser screenshot`: one page, one PNG.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use sibuna_browser::{Browser, Error};

use crate::arguments::{Flag, Flags, UsageError};

/// The flags `screenshot` accepts.
pub const FLAGS: &[Flag] = &[
    Flag { name: "--url", takes_value: true },
    Flag { name: "--out", takes_value: true },
    Flag { name: "--width", takes_value: true },
    Flag { name: "--height", takes_value: true },
    Flag { name: "--mobile", takes_value: false },
    Flag { name: "--no-wasm", takes_value: false },
];

/// The checked flags of `screenshot`.
#[derive(Debug)]
pub struct Settings {
    url: String,
    out: PathBuf,
    width: u32,
    height: u32,
    mobile: bool,
    no_wasm: bool,
}

impl Settings {
    /// Reads and checks the flags.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a missing `--url` or `--out` or an invalid size.
    pub fn read(flags: &Flags) -> Result<Settings, UsageError> {
        Ok(Settings {
            url: flags.required("--url")?.to_owned(),
            out: flags.required_path("--out")?,
            width: flags.number("--width", 1280, 10_000)?,
            height: flags.number("--height", 800, 10_000)?,
            mobile: flags.is_set("--mobile"),
            no_wasm: flags.is_set("--no-wasm"),
        })
    }
}

/// Loads the page, lets it settle for half a second, and writes the screenshot. Console
/// errors and exceptions are printed; they do not fail an ad-hoc screenshot.
///
/// # Errors
///
/// The browser's errors: launch, navigation, timeouts, writing the file.
pub fn run(settings: &Settings) -> Result<bool, Error> {
    let mut browser = Browser::launch(crate::browser_options())?;
    let mut page = browser.new_page()?;
    if settings.no_wasm {
        page.disable_webassembly()?;
    }
    page.set_viewport(settings.width, settings.height, settings.mobile)?;
    page.navigate(&settings.url)?;
    page.idle_for(Duration::from_millis(500))?;
    page.screenshot(&settings.out)?;
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "screenshot: {} -> {}", settings.url, settings.out.display());
    for message in page.console_messages().iter().filter(|message| message.is_error()) {
        let _ = writeln!(stdout, "  console {}: {}", message.level, message.text);
    }
    for exception in page.exceptions() {
        let _ = writeln!(stdout, "  exception: {}", exception.text);
    }
    Ok(true)
}
