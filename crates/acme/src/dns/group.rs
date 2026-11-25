//! Ending a process group: the one foreign call of this crate.
//!
//! The hook runs in a process group of its own. When it runs too long we end the
//! group, so that a program which the hook started ends with it. The standard library
//! can start a process in a new group and cannot signal a group, hence `kill(2)`.

#![allow(unsafe_code)]

use std::io;

#[cfg(unix)]
mod sys {
    use std::ffi::c_int;
    use std::io;

    /// `SIGKILL` of `<signal.h>`: 9 on every Unix.
    const SIGKILL: c_int = 9;

    unsafe extern "C" {
        /// `kill(2)`. `pid_t` is a C `int` on Linux, macOS and the BSDs.
        fn kill(process: c_int, signal: c_int) -> c_int;
    }

    pub fn kill_group(group: c_int) -> io::Result<()> {
        // SAFETY: `kill` takes two integers and keeps no pointer. The caller made sure
        // that `group` is above 1, so `-group` names one process group and neither
        // every process (-1) nor our own group (0).
        if unsafe { kill(-group, SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Sends `SIGKILL` to every process of the group `group`, which is the process number
/// of the group's first process. A number of 0 or 1, or one that does not fit, is
/// refused: those would name our own group or every process. Fails with the error of
/// the system, for example when the group has no process left. Without process groups
/// (not Unix) it reports [`io::ErrorKind::Unsupported`].
pub(crate) fn kill_group(group: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        match i32::try_from(group) {
            Ok(group) if group > 1 => sys::kill_group(group),
            _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = group;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_group_and_every_process_are_never_named() {
        for group in [0, 1, u32::MAX] {
            let error = kill_group(group).err().map(|error| error.kind());
            assert_eq!(error, Some(io::ErrorKind::InvalidInput), "{group}");
        }
    }
}
