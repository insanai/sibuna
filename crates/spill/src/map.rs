//! The bytes behind a cache: a file mapped into memory, or plain memory.
//!
//! This is the only module with foreign calls. It hands out no reference into the
//! mapping. [`Store::read`] and [`Store::write`] copy a few bytes in or out after a
//! bounds check, so a caller can neither run past the mapping nor hold a view of bytes
//! that another program may change.
//!
//! One hazard remains that no check here can remove. When another program shortens the
//! file while it is mapped, the next access beyond the new end raises a signal that ends
//! the process, and so does a read error of the disk. The cache keeps an exclusive lock
//! on its file and creates it for its owner alone.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;

/// The bytes of a cache.
pub(crate) enum Store {
    /// A mapped file. The file stays open, which keeps its lock.
    Mapped {
        /// The mapping. Dropped before the file.
        map: sys::Mapping,
        /// The open, locked file.
        file: File,
    },
    /// Memory that is lost with the process.
    Memory(Vec<u8>),
}

impl Store {
    /// Maps the first `len` bytes of `file` for reading and writing. The caller has
    /// checked that the file has exactly `len` bytes.
    ///
    /// # Errors
    ///
    /// The error of the mapping, or `Unsupported` on a platform without it.
    pub fn map(file: File, len: u64) -> io::Result<Self> {
        let len = usize::try_from(len).map_err(|_| io::ErrorKind::Unsupported)?;
        let map = sys::Mapping::new(&file, len)?;
        Ok(Self::Mapped { map, file })
    }

    /// `len` zero bytes of memory.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` when the memory cannot be had.
    pub fn memory(len: u64) -> io::Result<Self> {
        let len = usize::try_from(len).map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| io::ErrorKind::OutOfMemory)?;
        bytes.resize(len, 0);
        Ok(Self::Memory(bytes))
    }

    /// Whether the bytes outlive the process.
    pub fn is_persistent(&self) -> bool {
        matches!(self, Self::Mapped { .. })
    }

    /// Copies `out.len()` bytes that start at `offset` into `out`. Returns `false` and
    /// leaves `out` alone when the range does not lie inside the store.
    pub fn read(&self, offset: u64, out: &mut [u8]) -> bool {
        let Ok(offset) = usize::try_from(offset) else { return false };
        match self {
            Self::Mapped { map, .. } => map.read(offset, out),
            Self::Memory(bytes) => {
                let Some(end) = offset.checked_add(out.len()) else { return false };
                let Some(source) = bytes.get(offset..end) else { return false };
                out.copy_from_slice(source);
                true
            }
        }
    }

    /// Copies `bytes` into the store at `offset`. Returns `false` and writes nothing
    /// when the range does not lie inside the store.
    pub fn write(&mut self, offset: u64, bytes: &[u8]) -> bool {
        let Ok(offset) = usize::try_from(offset) else { return false };
        match self {
            Self::Mapped { map, .. } => map.write(offset, bytes),
            Self::Memory(memory) => {
                let Some(end) = offset.checked_add(bytes.len()) else { return false };
                let Some(target) = memory.get_mut(offset..end) else { return false };
                target.copy_from_slice(bytes);
                true
            }
        }
    }

    /// Asks the system to write every changed page to the disk and waits for it.
    ///
    /// # Errors
    ///
    /// The error of the file system. Memory has nothing to flush.
    pub fn flush(&self) -> io::Result<()> {
        match self {
            // A shared mapping and its file share their pages, so syncing the file
            // writes what was changed through the mapping.
            Self::Mapped { file, .. } => file.sync_data(),
            Self::Memory(_) => Ok(()),
        }
    }
}

/// Whether this platform maps files. Elsewhere a cache lives in memory.
pub(crate) const CAN_MAP: bool = sys::CAN_MAP;

#[cfg(all(unix, target_pointer_width = "64"))]
mod sys {
    use std::ffi::{c_int, c_void};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::ptr::NonNull;

    pub const CAN_MAP: bool = true;

    /// `PROT_READ | PROT_WRITE` of `<sys/mman.h>`, the same on Linux, macOS and the BSDs.
    const READ_WRITE: c_int = 1 | 2;
    /// `MAP_SHARED`: writes reach the file and survive the process.
    const SHARED: c_int = 1;

    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            descriptor: c_int,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
    }

    /// A shared mapping of a file. It is unmapped when dropped.
    pub struct Mapping {
        start: NonNull<u8>,
        len: usize,
    }

    // SAFETY: the mapping is plain memory owned by this value. Nothing in it is tied to
    // the thread that made it, and it is only reached through `&self` and `&mut self`.
    unsafe impl Send for Mapping {}

    impl Mapping {
        pub fn new(file: &File, len: usize) -> io::Result<Self> {
            if len == 0 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            // SAFETY: a null address lets the system choose the place, so no existing
            // memory is replaced. The descriptor is open for the call. The result is
            // checked before use.
            let address = unsafe {
                mmap(std::ptr::null_mut(), len, READ_WRITE, SHARED, file.as_raw_fd(), 0)
            };
            // `MAP_FAILED` is the address of all one bits.
            if address as usize == usize::MAX {
                return Err(io::Error::last_os_error());
            }
            let start = NonNull::new(address.cast::<u8>())
                .ok_or_else(|| io::Error::other("the mapping has no address"))?;
            Ok(Self { start, len })
        }

        pub fn read(&self, offset: usize, out: &mut [u8]) -> bool {
            let inside = offset.checked_add(out.len()).is_some_and(|end| end <= self.len);
            if !inside {
                return false;
            }
            // SAFETY: `offset + out.len() <= self.len`, so the source lies inside the
            // mapping, which is readable until `self` is dropped. `out` is a separate
            // allocation, so the ranges do not overlap. Bytes are valid for any content.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.start.as_ptr().add(offset),
                    out.as_mut_ptr(),
                    out.len(),
                );
            }
            true
        }

        pub fn write(&mut self, offset: usize, bytes: &[u8]) -> bool {
            let inside = offset.checked_add(bytes.len()).is_some_and(|end| end <= self.len);
            if !inside {
                return false;
            }
            // SAFETY: `offset + bytes.len() <= self.len`, so the target lies inside the
            // mapping, which is writable until `self` is dropped. `bytes` is a separate
            // allocation, so the ranges do not overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.start.as_ptr().add(offset),
                    bytes.len(),
                );
            }
            true
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: `start` and `len` are the address and the length that `mmap`
            // returned and was given, and no pointer into the mapping outlives `self`.
            // A failure leaves the mapping in place until the process ends.
            unsafe {
                munmap(self.start.as_ptr().cast::<c_void>(), self.len);
            }
        }
    }
}

#[cfg(not(all(unix, target_pointer_width = "64")))]
mod sys {
    use std::fs::File;
    use std::io;

    pub const CAN_MAP: bool = false;

    /// A mapping that cannot exist on this platform.
    pub enum Mapping {}

    impl Mapping {
        pub fn new(_file: &File, _len: usize) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }

        pub fn read(&self, _offset: usize, _out: &mut [u8]) -> bool {
            match *self {}
        }

        pub fn write(&mut self, _offset: usize, _bytes: &[u8]) -> bool {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_refuses_every_range_outside_itself() {
        let mut store = Store::memory(16).unwrap_or_else(|_| Store::Memory(Vec::new()));
        assert!(store.write(8, &[1; 8]));
        assert!(!store.write(9, &[1; 8]));
        assert!(!store.write(u64::MAX, &[1]));
        let mut out = [0; 8];
        assert!(store.read(8, &mut out));
        assert_eq!(out, [1; 8]);
        assert!(!store.read(16, &mut out[..1]));
        assert!(store.read(16, &mut []));
        assert!(!store.is_persistent());
    }
}
