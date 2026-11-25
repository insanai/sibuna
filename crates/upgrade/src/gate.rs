//! The Unix socket on which a running process waits for its replacement.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The longest socket path. A Unix socket address holds 104 bytes on the smallest
/// system, and the private directory adds up to 18.
const MAX_PATH: usize = 86;

/// The listening socket of the old process. Dropping it removes the socket file, unless
/// another process has put its own socket there or [`Gate::keep_file`] was called. It
/// can be shared between the thread that accepts and the owner that ends it.
pub struct Gate {
    listener: UnixListener,
    path: PathBuf,
    /// The device and inode of the file we created.
    identity: Option<(u64, u64)>,
    keep: AtomicBool,
}

/// The device and inode of the file at `path`, which tell our socket from a later one.
fn identity(path: &Path) -> Option<(u64, u64)> {
    fs::symlink_metadata(path).ok().map(|found| (found.dev(), found.ino()))
}

impl Gate {
    /// Binds the socket at `path`. The file never has a mode wider than 0600: it is
    /// bound in a private directory and renamed to `path`. A socket file that is
    /// already there is replaced, because the caller has either found nobody
    /// answering on it or has just taken over from the process that did.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` when the path holds a file that is not a socket, `InvalidInput`
    /// for a path longer than 86 bytes, and the error of creating the directory, of
    /// binding or of renaming.
    pub fn listen(path: &Path) -> io::Result<Self> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(found) if !found.file_type().is_socket() => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the path holds a file that is not a socket",
                ));
            }
            Ok(_) => {}
        }
        if path.as_os_str().len() > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the path is longer than {MAX_PATH} bytes, the most a Unix socket takes"),
            ));
        }
        let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty());
        let private =
            parent.unwrap_or(Path::new(".")).join(format!(".sibuna-up-{}", std::process::id()));
        // A directory of this name can only be the remains of an earlier process.
        let _ = fs::remove_file(private.join("s"));
        let _ = fs::remove_dir(&private);
        fs::DirBuilder::new().mode(0o700).create(&private)?;
        let bound = private.join("s");
        let result = UnixListener::bind(&bound).and_then(|listener| {
            fs::set_permissions(&bound, fs::Permissions::from_mode(0o600))?;
            fs::rename(&bound, path)?;
            Ok(listener)
        });
        let _ = fs::remove_file(&bound);
        let _ = fs::remove_dir(&private);
        let listener = result?;
        let identity = identity(path);
        Ok(Self { listener, path: path.to_path_buf(), identity, keep: AtomicBool::new(false) })
    }

    /// Waits for the next connection.
    ///
    /// # Errors
    ///
    /// The error of `accept`. The gate stays usable.
    pub fn accept(&self) -> io::Result<UnixStream> {
        self.listener.accept().map(|(stream, _)| stream)
    }

    /// The path of the socket file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Leaves the socket file in place from now on. The old process calls this after a
    /// handoff: the replacement puts its own socket at the path, and a removal by the
    /// old process could hit that one.
    pub fn keep_file(&self) {
        self.keep.store(true, Ordering::Release);
    }

    /// Removes the socket file, when it is still the file of this gate and
    /// [`Gate::keep_file`] was not called. A process that ends calls this, because a
    /// thread that waits in [`Gate::accept`] keeps the gate from being dropped.
    pub fn remove_file(&self) {
        if !self.keep.load(Ordering::Acquire) && identity(&self.path) == self.identity {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.remove_file();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("sbup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("directory");
        directory
    }

    #[test]
    fn the_socket_has_mode_0600_and_goes_with_the_gate() {
        let directory = scratch("mode");
        let path = directory.join("up.sock");
        let gate = Gate::listen(&path).expect("listen");
        let mode = fs::metadata(&path).expect("file").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(UnixStream::connect(&path).is_ok());
        drop(gate);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&directory).expect("directory").count(), 0);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_later_gate_takes_the_path_and_the_earlier_one_leaves_it() {
        let directory = scratch("later");
        let path = directory.join("up.sock");
        let first = Gate::listen(&path).expect("first");
        let second = Gate::listen(&path).expect("second");
        drop(first);
        assert!(path.exists(), "the first gate removed the file of the second");
        let stream = UnixStream::connect(&path).expect("connect");
        assert!(second.accept().is_ok());
        drop(stream);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_kept_file_stays_and_a_plain_file_is_not_replaced() {
        let directory = scratch("kept");
        let path = directory.join("up.sock");
        let gate = Gate::listen(&path).expect("listen");
        gate.keep_file();
        drop(gate);
        assert!(path.exists());
        let plain = directory.join("notes.txt");
        fs::write(&plain, "x").expect("write");
        let error = Gate::listen(&plain).err().expect("refused");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let long = directory.join("x".repeat(90));
        assert_eq!(Gate::listen(&long).err().expect("long").kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_dir_all(&directory);
    }
}
