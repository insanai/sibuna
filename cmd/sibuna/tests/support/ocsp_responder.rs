//! An OCSP responder for the tests of stapling (SID 0021). It speaks for a test
//! authority: it answers a POST with a response that the key of that authority signs,
//! or the key of a delegated signer that the authority certified.
//!
//! The test file that includes this module names the test authority `authority`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_acme::ocsp::Status;
use sibuna_acme::ocsp::build::{Reply, asked_serial, response};
use sibuna_acme::{KeyPair, x509};

use crate::authority::{Authority, ISSUER};

/// What the test sets and reads.
pub struct Responder {
    /// The status of the next answers.
    pub status: Mutex<Status>,
    /// How long the next answers are valid, in seconds.
    pub validity: AtomicU64,
    /// Answer 503 instead of a response.
    pub down: AtomicBool,
    /// Sign with the delegated key and add its certificate.
    pub delegated: AtomicBool,
    /// The questions received so far.
    pub asked: AtomicUsize,
    authority: Arc<Authority>,
    delegate_key: KeyPair,
    delegate: Vec<u8>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

impl Responder {
    /// Starts the responder on a free loopback port. The certificates that `authority`
    /// issues from now on name it.
    pub fn start(authority: &Arc<Authority>) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/ocsp", listener.local_addr().unwrap());
        *authority.ocsp_url.lock().unwrap() = Some(url);
        let delegate_key = KeyPair::generate().unwrap();
        let template = x509::Template {
            issuer: ISSUER,
            subject: "Sibuna Test Responder",
            not_before: now() - 60,
            not_after: now() + 86_400,
            serial: 2,
            ocsp_signing: true,
            ..x509::Template::default()
        };
        let delegate =
            x509::write(&template, &delegate_key.subject_public_key_info(), authority.signer())
                .unwrap();
        let responder = Arc::new(Self {
            status: Mutex::new(Status::Good),
            validity: AtomicU64::new(3600),
            down: AtomicBool::new(false),
            delegated: AtomicBool::new(false),
            asked: AtomicUsize::new(0),
            authority: Arc::clone(authority),
            delegate_key,
            delegate,
        });
        let serving = Arc::clone(&responder);
        std::thread::spawn(move || {
            for socket in listener.incoming().flatten() {
                let responder = Arc::clone(&serving);
                std::thread::spawn(move || responder.serve(socket));
            }
        });
        responder
    }

    /// Reads one POST and answers it.
    fn serve(&self, mut socket: TcpStream) {
        let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut length = 0;
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 2 {
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap_or(0);
            }
            line.clear();
        }
        let mut request = vec![0; length];
        if reader.read_exact(&mut request).is_err() {
            return;
        }
        self.asked.fetch_add(1, Ordering::Relaxed);
        let answer = match self.answer(&request) {
            Some(body) if !self.down.load(Ordering::Relaxed) => body,
            _ => {
                let _ = socket.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                );
                return;
            }
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            answer.len()
        );
        let _ = socket.write_all(head.as_bytes());
        let _ = socket.write_all(&answer);
    }

    /// The response about the certificate that `request` asks about.
    fn answer(&self, request: &[u8]) -> Option<Vec<u8>> {
        let leaf = self.authority.issued(&asked_serial(request)?)?;
        let root = self.authority.root_der();
        let delegated = self.delegated.load(Ordering::Relaxed);
        // One second in the past: the clocks of the test and of the daemon are one.
        let this_update = now() - 1;
        let reply = Reply {
            leaf: &leaf,
            issuer: &root,
            status: *self.status.lock().unwrap(),
            this_update,
            next_update: this_update + 1 + self.validity.load(Ordering::Relaxed),
            delegate: delegated.then_some(&self.delegate[..]),
        };
        let signer = if delegated { &self.delegate_key } else { self.authority.signer() };
        response(&reply, signer).ok()
    }
}
