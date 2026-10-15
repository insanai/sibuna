//! Screencast frames written as numbered PNG files: the "video" of a page.
//!
//! Chromium sends a frame after each visual change, and the next only after the previous
//! one is acknowledged, so frames are spaced by paint activity rather than a fixed rate.
//! `frames.txt` lists each file with Chromium's timestamp so the sequence can be replayed
//! at its real pace (for example `ffmpeg -f concat` on a machine that has it).

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sibuna_encoding::base64;

use crate::error::Error;

/// How a recording is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordingOptions {
    /// The most frames written; later frames are acknowledged and counted but not saved.
    /// Default: 3,000.
    pub max_frames: usize,
    /// Keep only every n-th frame Chromium paints. Default: 1.
    pub every_nth_frame: u32,
    /// Scale frames down to at most this size in CSS pixels; zero keeps the viewport size.
    /// Default: 0 by 0.
    pub max_width: u32,
    /// See `max_width`.
    pub max_height: u32,
}

impl Default for RecordingOptions {
    fn default() -> Self {
        RecordingOptions { max_frames: 3000, every_nth_frame: 1, max_width: 0, max_height: 0 }
    }
}

/// The result of a finished recording.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recording {
    /// Where the frames and `frames.txt` are.
    pub directory: PathBuf,
    /// How many frames were written.
    pub frame_count: usize,
    /// How many frames arrived after `max_frames` and were not written.
    pub dropped_count: usize,
}

/// A recording in progress.
#[derive(Debug)]
pub(crate) struct Recorder {
    directory: PathBuf,
    max_frames: usize,
    /// One line per written frame: its file name and timestamp.
    index: String,
    frame_count: usize,
    dropped_count: usize,
}

impl Recorder {
    /// Creates `directory` (and its parents) for a new recording.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the directory cannot be created.
    pub(crate) fn begin(directory: &Path, max_frames: usize) -> Result<Recorder, Error> {
        fs::create_dir_all(directory).map_err(|error| {
            Error::io(format!("creating the frame directory {}", directory.display()), error)
        })?;
        Ok(Recorder {
            directory: directory.to_owned(),
            max_frames,
            index: String::new(),
            frame_count: 0,
            dropped_count: 0,
        })
    }

    /// Decodes one base64 PNG frame and writes it as the next numbered file.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] for invalid base64 and [`Error::Io`] when writing fails.
    pub(crate) fn write_frame(&mut self, data: &str, timestamp: f64) -> Result<(), Error> {
        if self.frame_count >= self.max_frames {
            self.dropped_count += 1;
            return Ok(());
        }
        let png = base64::decode(base64::STANDARD, data.as_bytes())
            .map_err(|error| Error::Protocol(format!("a screencast frame: {error}")))?;
        let name = format!("frame-{:05}.png", self.frame_count + 1);
        let path = self.directory.join(&name);
        fs::write(&path, png)
            .map_err(|error| Error::io(format!("writing {}", path.display()), error))?;
        self.frame_count += 1;
        // Writing into a String cannot fail.
        let _ = writeln!(self.index, "{name} {timestamp:.3}");
        Ok(())
    }

    /// Writes `frames.txt` and returns the summary.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the index cannot be written.
    pub(crate) fn end(self) -> Result<Recording, Error> {
        let path = self.directory.join("frames.txt");
        fs::write(&path, &self.index)
            .map_err(|error| Error::io(format!("writing {}", path.display()), error))?;
        Ok(Recording {
            directory: self.directory,
            frame_count: self.frame_count,
            dropped_count: self.dropped_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_numbered_frames_an_index_and_respects_the_bound() {
        let directory = std::env::temp_dir()
            .join(format!("sibuna-browser-recorder-test-{}", std::process::id()));
        let mut recorder = Recorder::begin(&directory, 2).unwrap();
        let data = base64::encode(base64::STANDARD, b"\x89PNG fake");
        for timestamp in [1.0, 1.25, 1.5] {
            recorder.write_frame(&data, timestamp).unwrap();
        }
        assert!(recorder.write_frame("not base64!", 2.0).is_ok(), "past the bound: not decoded");
        let recording = recorder.end().unwrap();
        assert_eq!((recording.frame_count, recording.dropped_count), (2, 2));
        assert_eq!(fs::read(directory.join("frame-00002.png")).unwrap(), b"\x89PNG fake");
        let index = fs::read_to_string(directory.join("frames.txt")).unwrap();
        assert_eq!(index, "frame-00001.png 1.000\nframe-00002.png 1.250\n");
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn refuses_invalid_base64() {
        let directory = std::env::temp_dir()
            .join(format!("sibuna-browser-recorder-bad-{}", std::process::id()));
        let mut recorder = Recorder::begin(&directory, 2).unwrap();
        assert!(matches!(recorder.write_frame("@@@@", 0.0), Err(Error::Protocol(_))));
        fs::remove_dir_all(&directory).unwrap();
    }
}
