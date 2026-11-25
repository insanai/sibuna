//! The system calls of the handoff that the standard library does not wrap: sending and
//! receiving descriptors with `SCM_RIGHTS`, the credentials of the peer of a Unix
//! socket, the type of a socket, and the signal that ends a silent replacement.
//!
//! This is the only unsafe code of the crate. It is built for Linux on the processors
//! whose socket constants are the common ones. Elsewhere every function reports
//! [`io::ErrorKind::Unsupported`], and [`SUPPORTED`] is false.

#![allow(unsafe_code)]

/// The most descriptors one message carries.
pub(crate) const MAX_DESCRIPTORS: usize = 64;

/// The process at the other end of a Unix socket, as the kernel recorded it when the
/// connection was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The process id. Zero when the process is not visible from here.
    pub pid: i32,
    /// The effective user id.
    pub uid: u32,
    /// The effective group id.
    pub gid: u32,
}

/// What kind of socket a descriptor is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketKind {
    /// A stream socket that listens.
    Listening,
    /// A stream socket that does not listen.
    Stream,
    /// A datagram socket.
    Datagram,
    /// Another type of socket.
    Other,
}

/// True when this platform can pass descriptors and read peer credentials here.
pub const SUPPORTED: bool = cfg!(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
));

pub(crate) use imp::{effective_user, end_process, peer, receive, send, socket_kind};

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
))]
mod imp {
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    use super::{MAX_DESCRIPTORS, Peer, SocketKind};

    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const SO_TYPE: i32 = 3;
    const SO_PEERCRED: i32 = 17;
    const SO_ACCEPTCONN: i32 = 30;
    const SOCK_STREAM: i32 = 1;
    const SOCK_DGRAM: i32 = 2;
    const MSG_CTRUNC: i32 = 0x8;
    const MSG_NOSIGNAL: i32 = 0x4000;
    const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
    const SIGKILL: i32 = 9;

    /// `struct iovec`.
    #[repr(C)]
    struct IoVec {
        base: *mut c_void,
        length: usize,
    }

    /// `struct msghdr`. The two lengths are `size_t` in the kernel. A C library that
    /// declares them narrower pads them to this layout.
    #[repr(C)]
    struct MsgHdr {
        name: *mut c_void,
        name_length: u32,
        iov: *mut IoVec,
        iov_count: usize,
        control: *mut c_void,
        control_length: usize,
        flags: i32,
    }

    /// `struct cmsghdr` followed by the descriptors of one `SCM_RIGHTS` message. The
    /// descriptors start where `CMSG_DATA` puts them: after the header, which is 16
    /// bytes on a 64-bit system and 12 on a 32-bit one, and `repr(C)` gives the same.
    #[repr(C)]
    struct Control {
        length: usize,
        level: i32,
        kind: i32,
        descriptors: [i32; MAX_DESCRIPTORS],
    }

    /// The bytes of the control header, `CMSG_LEN(0)`.
    const HEADER: usize = std::mem::offset_of!(Control, descriptors);

    /// `struct ucred`.
    #[repr(C)]
    struct UCred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    unsafe extern "C" {
        fn sendmsg(fd: i32, message: *const MsgHdr, flags: i32) -> isize;
        fn recvmsg(fd: i32, message: *mut MsgHdr, flags: i32) -> isize;
        fn getsockopt(fd: i32, level: i32, name: i32, value: *mut c_void, length: *mut u32)
        -> i32;
        fn geteuid() -> u32;
        fn kill(pid: i32, signal: i32) -> i32;
    }

    fn empty_control() -> Control {
        Control { length: 0, level: 0, kind: 0, descriptors: [-1; MAX_DESCRIPTORS] }
    }

    /// Sends `bytes` and `descriptors` in one message. Returns the bytes sent, which is
    /// less than `bytes.len()` only when the socket buffer is nearly full. The
    /// descriptors travel with the first byte.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for no bytes or more than [`MAX_DESCRIPTORS`] descriptors, and the
    /// error of `sendmsg`. A closed peer gives `BrokenPipe` and no signal.
    pub(crate) fn send(
        stream: &UnixStream,
        bytes: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> io::Result<usize> {
        if bytes.is_empty() || descriptors.len() > MAX_DESCRIPTORS {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "message out of bounds"));
        }
        let mut control = empty_control();
        control.length = HEADER + 4 * descriptors.len();
        control.level = SOL_SOCKET;
        control.kind = SCM_RIGHTS;
        for (slot, descriptor) in control.descriptors.iter_mut().zip(descriptors) {
            *slot = descriptor.as_raw_fd();
        }
        let mut iov = IoVec { base: bytes.as_ptr().cast_mut().cast(), length: bytes.len() };
        // `CMSG_SPACE`: the length of the control message, rounded up to a word.
        let word = size_of::<usize>();
        let space = control.length.div_ceil(word) * word;
        let message = MsgHdr {
            name: std::ptr::null_mut(),
            name_length: 0,
            iov: &mut iov,
            iov_count: 1,
            control: if descriptors.is_empty() {
                std::ptr::null_mut()
            } else {
                (&raw mut control).cast()
            },
            control_length: if descriptors.is_empty() { 0 } else { space },
            flags: 0,
        };
        // SAFETY: `message` points at one live `iovec` over `bytes`, which the kernel
        // only reads, and at `control`, which is at least `space` bytes long because
        // `space` does not exceed the size of `Control`. The descriptors in it are open:
        // the borrows in `descriptors` outlive the call.
        let sent = unsafe { sendmsg(stream.as_raw_fd(), &message, MSG_NOSIGNAL) };
        usize::try_from(sent).map_err(|_| io::Error::last_os_error())
    }

    /// Receives up to `buffer.len()` bytes and the descriptors that came with them,
    /// which are appended to `descriptors` and close on `exec`. Returns the bytes
    /// received. Zero means that the peer closed.
    ///
    /// # Errors
    ///
    /// The error of `recvmsg`, and `InvalidData` when the control message was cut short
    /// or is not one `SCM_RIGHTS` message. Descriptors received before the fault was
    /// seen are closed.
    pub(crate) fn receive(
        stream: &UnixStream,
        buffer: &mut [u8],
        descriptors: &mut Vec<OwnedFd>,
    ) -> io::Result<usize> {
        let mut control = empty_control();
        let mut iov = IoVec { base: buffer.as_mut_ptr().cast(), length: buffer.len() };
        let mut message = MsgHdr {
            name: std::ptr::null_mut(),
            name_length: 0,
            iov: &mut iov,
            iov_count: 1,
            control: (&raw mut control).cast(),
            control_length: size_of::<Control>(),
            flags: 0,
        };
        // SAFETY: `message` points at one live `iovec` over `buffer`, which is writable
        // for its whole length, and at `control`, which is writable for the length
        // given. The kernel writes inside both and nowhere else.
        let count = unsafe { recvmsg(stream.as_raw_fd(), &mut message, MSG_CMSG_CLOEXEC) };
        let count = usize::try_from(count).map_err(|_| io::Error::last_os_error())?;
        let received = take_descriptors(&control, message.control_length);
        let whole = message.flags & MSG_CTRUNC == 0;
        match received {
            Some(received) if whole => {
                descriptors.extend(received);
                Ok(count)
            }
            // The descriptors that did arrive close here.
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "bad control message")),
        }
    }

    /// Takes ownership of the descriptors that the kernel wrote into `control`, of
    /// which `filled` bytes are used. `None` when the control data is not empty and is
    /// not exactly one `SCM_RIGHTS` message; the descriptors of such a message, if it
    /// has any, are closed.
    fn take_descriptors(control: &Control, filled: usize) -> Option<Vec<OwnedFd>> {
        if filled == 0 {
            return Some(Vec::new());
        }
        if filled < HEADER || control.length < HEADER || control.length > filled {
            return None;
        }
        let rights = control.level == SOL_SOCKET && control.kind == SCM_RIGHTS;
        if !rights {
            // Another kind of message carries no descriptor, so nothing leaks.
            return None;
        }
        let count = ((control.length - HEADER) / 4).min(MAX_DESCRIPTORS);
        let owned: Vec<OwnedFd> = control.descriptors[..count]
            .iter()
            .filter(|descriptor| **descriptor >= 0)
            // SAFETY: the kernel installed each of these descriptors in this process
            // for this message, and nothing else knows their numbers, so each is open
            // and owned by nobody.
            .map(|descriptor| unsafe { OwnedFd::from_raw_fd(*descriptor) })
            .collect();
        let word = size_of::<usize>();
        // A second control message would follow the first after its padding.
        let single = filled <= control.length.div_ceil(word) * word;
        (single && owned.len() == count).then_some(owned)
    }

    /// Reads one integer socket option.
    fn option(socket: BorrowedFd<'_>, name: i32) -> io::Result<i32> {
        let mut value = 0i32;
        let mut length = 4u32;
        // SAFETY: `value` is four writable bytes and `length` says so. The kernel
        // writes at most that many.
        let status = unsafe {
            getsockopt(socket.as_raw_fd(), SOL_SOCKET, name, (&raw mut value).cast(), &mut length)
        };
        if status == 0 { Ok(value) } else { Err(io::Error::last_os_error()) }
    }

    /// Says what kind of socket `socket` is.
    ///
    /// # Errors
    ///
    /// The error of `getsockopt`, for example when the descriptor is not a socket.
    pub(crate) fn socket_kind(socket: BorrowedFd<'_>) -> io::Result<SocketKind> {
        Ok(match option(socket, SO_TYPE)? {
            SOCK_STREAM if option(socket, SO_ACCEPTCONN)? != 0 => SocketKind::Listening,
            SOCK_STREAM => SocketKind::Stream,
            SOCK_DGRAM => SocketKind::Datagram,
            _ => SocketKind::Other,
        })
    }

    /// Reads the credentials of the process at the other end of `stream`.
    ///
    /// # Errors
    ///
    /// The error of `getsockopt`.
    pub(crate) fn peer(stream: &UnixStream) -> io::Result<Peer> {
        let mut found = UCred { pid: 0, uid: u32::MAX, gid: u32::MAX };
        let mut length = size_of::<UCred>() as u32;
        // SAFETY: `found` is a writable `ucred` and `length` is its size. The kernel
        // writes at most that many bytes.
        let status = unsafe {
            getsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_PEERCRED,
                (&raw mut found).cast(),
                &mut length,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of::<UCred>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short peer credentials"));
        }
        Ok(Peer { pid: found.pid, uid: found.uid, gid: found.gid })
    }

    /// The effective user id of this process.
    pub(crate) fn effective_user() -> u32 {
        // SAFETY: `geteuid` takes nothing and cannot fail.
        unsafe { geteuid() }
    }

    /// Sends SIGKILL to the process `pid`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a pid below 2, which would name a process group or init, and
    /// the error of `kill`.
    pub(crate) fn end_process(pid: i32) -> io::Result<()> {
        if pid < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no process to end"));
        }
        // SAFETY: `kill` takes two integers. A positive pid names one process.
        if unsafe { kill(pid, SIGKILL) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
)))]
mod imp {
    use std::io;
    use std::os::fd::{BorrowedFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    use super::{Peer, SocketKind};

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "descriptor passing needs Linux"))
    }

    /// Refuses: see the module.
    pub(crate) fn send(_: &UnixStream, _: &[u8], _: &[BorrowedFd<'_>]) -> io::Result<usize> {
        unsupported()
    }

    /// Refuses: see the module.
    pub(crate) fn receive(
        _: &UnixStream,
        _: &mut [u8],
        _: &mut Vec<OwnedFd>,
    ) -> io::Result<usize> {
        unsupported()
    }

    /// Refuses: see the module.
    pub(crate) fn socket_kind(_: BorrowedFd<'_>) -> io::Result<SocketKind> {
        unsupported()
    }

    /// Refuses: see the module.
    pub(crate) fn peer(_: &UnixStream) -> io::Result<Peer> {
        unsupported()
    }

    /// No user: nothing compares equal to it.
    pub(crate) fn effective_user() -> u32 {
        u32::MAX
    }

    /// Refuses: see the module.
    pub(crate) fn end_process(_: i32) -> io::Result<()> {
        unsupported()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn a_descriptor_crosses_the_socket_and_still_names_the_same_listener() {
        let (left, right) = UnixStream::pair().expect("pair");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        assert_eq!(send(&left, b"x", &[listener.as_fd()]).expect("send"), 1);
        let mut held = Vec::new();
        let mut byte = [0u8; 1];
        assert_eq!(receive(&right, &mut byte, &mut held).expect("receive"), 1);
        assert_eq!(held.len(), 1);
        let copy = TcpListener::from(held.remove(0));
        assert_eq!(copy.local_addr().expect("address"), address);
        // The original is closed. The copy keeps the listener open.
        drop(listener);
        let mut client = std::net::TcpStream::connect(address).expect("connect");
        let (mut accepted, _) = copy.accept().expect("accept");
        client.write_all(b"hi").expect("write");
        let mut bytes = [0u8; 2];
        accepted.read_exact(&mut bytes).expect("read");
        assert_eq!(&bytes, b"hi");
    }

    #[test]
    fn the_most_descriptors_fit_and_one_more_is_refused() {
        let (left, right) = UnixStream::pair().expect("pair");
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let many = vec![socket.as_fd(); MAX_DESCRIPTORS];
        send(&left, b"m", &many).expect("send");
        let mut held = Vec::new();
        receive(&right, &mut [0u8; 1], &mut held).expect("receive");
        assert_eq!(held.len(), MAX_DESCRIPTORS);
        let more = vec![socket.as_fd(); MAX_DESCRIPTORS + 1];
        assert_eq!(
            send(&left, b"m", &more).expect_err("too many").kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_message_without_descriptors_brings_none() {
        let (left, right) = UnixStream::pair().expect("pair");
        send(&left, b"plain", &[]).expect("send");
        let mut held = Vec::new();
        let mut bytes = [0u8; 8];
        assert_eq!(receive(&right, &mut bytes, &mut held).expect("receive"), 5);
        assert!(held.is_empty());
        drop(left);
        assert_eq!(receive(&right, &mut bytes, &mut held).expect("end"), 0);
    }

    #[test]
    fn the_peer_of_a_pair_is_this_process() {
        let (left, _right) = UnixStream::pair().expect("pair");
        let found = peer(&left).expect("peer");
        assert_eq!(found.pid, std::process::id() as i32);
        assert_eq!(found.uid, effective_user());
    }

    #[test]
    fn the_kind_of_a_socket_is_told() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let datagram = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let stream = std::net::TcpStream::connect(listener.local_addr().expect("a")).expect("c");
        assert_eq!(socket_kind(listener.as_fd()).expect("kind"), SocketKind::Listening);
        assert_eq!(socket_kind(datagram.as_fd()).expect("kind"), SocketKind::Datagram);
        assert_eq!(socket_kind(stream.as_fd()).expect("kind"), SocketKind::Stream);
        let file = std::fs::File::open("/proc/self/exe").expect("file");
        assert!(socket_kind(file.as_fd()).is_err());
    }

    #[test]
    fn init_and_process_groups_are_never_signalled() {
        for pid in [-1, 0, 1] {
            assert_eq!(end_process(pid).expect_err("refused").kind(), io::ErrorKind::InvalidInput);
        }
    }
}
