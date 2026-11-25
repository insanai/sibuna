//! OCSP stapling in the certificate thread (SID 0021): it asks the responder that a
//! served certificate names, checks the answer, and hands it to the handshakes.
//!
//! ```text
//!   certificate installed --> ask --> good     --> store, staple, ask again at half
//!                                 --> revoked  --> staple nothing, renew at once
//!                                 --> failure  --> ask again after the retry delay
//!   window of the staple ends --> remove it from the handshakes
//! ```
//!
//! A certificate that names no responder has no state here, and nobody is asked.

use std::sync::atomic::Ordering;
use std::time::Duration;

use sibuna_acme::ocsp::{self, Answer, Responder, Status};
use sibuna_acme::store::Store;
use sibuna_acme::{Error, ari, schedule};

use super::super::Event;
use super::authority::Ready;
use super::{Driver, Entry, Source, now};

/// The longest wait for the answer of a responder.
const ASK_LIMIT: Duration = Duration::from_secs(15);

/// What the thread remembers of the responder of one served certificate.
pub(super) struct Stapling {
    responder: Responder,
    /// When the responder is asked next. `u64::MAX`: never.
    next: u64,
    /// The end of the window of the response that the handshakes staple now.
    until: Option<u64>,
    failures: u32,
    /// The responder said that the certificate is revoked.
    revoked: bool,
}

impl Stapling {
    /// The state of a certificate that was just installed: nothing is stapled, and the
    /// responder is asked at once.
    pub fn new(responder: Responder) -> Self {
        Self { responder, next: 0, until: None, failures: 0, revoked: false }
    }

    /// Whether a response is stapled now.
    pub fn is_stapled(&self) -> bool {
        self.until.is_some()
    }

    /// Whether the responder said that the certificate is revoked. Its renewal is then
    /// due, whatever the authority says about the renewal time.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// The word of `show certs`: `good` while a response is stapled, `revoked`, or `-`.
    pub fn word(&self) -> &'static str {
        match (self.revoked, self.until) {
            (true, _) => "revoked",
            (false, Some(_)) => "good",
            (false, None) => "-",
        }
    }

    /// The time at which the thread looks at the staple again: the next question, or
    /// the end of the window of the stapled response.
    pub fn wake_at(&self) -> u64 {
        self.next.min(self.until.unwrap_or(u64::MAX))
    }

    /// Takes a good answer that is stapled from `now` on.
    fn accept(&mut self, answer: &Answer, now: u64) {
        self.until = Some(answer.next_update);
        self.next = ocsp::refresh_at(answer, now);
        self.failures = 0;
    }
}

/// The responder that the leaf of a DER chain names, when the chain has the issuer.
pub(super) fn responder(chain: &[Vec<u8>]) -> Option<Responder> {
    Responder::find(chain.first()?, chain.get(1)?)
}

/// Asks the responder through the client of the first authority. The responder speaks
/// plain HTTP, so the trust roots of that client play no part.
fn ask(ready: &Ready, responder: &Responder) -> Result<Vec<u8>, Error> {
    let call = responder.call();
    let exchange = async {
        tokio::time::timeout(ASK_LIMIT, ready.first.client.call(&call, ocsp::MAX_RESPONSE)).await
    };
    let response = match ready.runtime.block_on(exchange) {
        Ok(result) => result.map_err(|error| Error::stapling(error.message))?,
        Err(_) => return Err(Error::stapling(format!("{}: no answer in time.", call.url))),
    };
    if response.status != 200 {
        let (url, status) = (&call.url, response.status);
        return Err(Error::stapling(format!("{url}: the responder answered {status}.")));
    }
    Ok(response.body)
}

impl Driver {
    /// Staples the stored response of a certificate that was just loaded, when it is
    /// still good. The responder is then asked at the usual time, not at once.
    pub(super) fn restore_staple(&self, store: &Store, name: &str, entry: &mut Entry) {
        let Some(stapling) = entry.stapling.as_mut() else { return };
        let Some(stored) = store.load_staple(name) else { return };
        let now = now();
        match stapling.responder.check(&stored, now) {
            Ok(answer) if answer.status == Status::Good => {
                stapling.accept(&answer, now);
                self.shared.staple(name, Some(stored));
            }
            _ => store.clear_staple(name),
        }
    }

    /// Looks at the staple of `name`: removes one whose window ended, and asks the
    /// responder when the question is due. A local certificate names no responder.
    pub(super) fn staple(&self, source: &Source<'_>, name: &str, entry: &mut Entry) {
        let Source::Acme(ready) = source else { return };
        let Some(mut stapling) = entry.stapling.take() else { return };
        let store = &ready.at(entry.issued_by).store;
        let now = now();
        let mut changed = false;
        if stapling.until.is_some_and(|until| until <= now) {
            stapling.until = None;
            self.shared.staple(name, None);
            store.clear_staple(name);
            changed = true;
        }
        if stapling.next <= now && self.shared.ordering.load(Ordering::Acquire) {
            self.refresh(ready, store, name, entry, &mut stapling);
            changed = true;
        }
        entry.stapling = Some(stapling);
        if changed {
            self.publish(name, entry, None);
        }
    }

    /// Asks the responder once and acts on the answer.
    fn refresh(
        &self,
        ready: &Ready,
        store: &Store,
        name: &str,
        entry: &mut Entry,
        stapling: &mut Stapling,
    ) {
        let now = now();
        let asked = ask(ready, &stapling.responder).and_then(|body| {
            let answer = stapling.responder.check(&body, now)?;
            Ok((answer, body))
        });
        let failure = match asked {
            Ok((answer, body)) if answer.status == Status::Good => {
                let first = !stapling.is_stapled();
                stapling.accept(&answer, now);
                // A response that cannot be stored is stapled all the same.
                let _ = store.save_staple(name, &body);
                self.shared.staple(name, Some(body));
                if first {
                    let until = answer.next_update;
                    (self.report)(&Event::Stapled { name: name.to_owned(), until });
                }
                return;
            }
            Ok((answer, _)) if answer.status == Status::Revoked => {
                return self.revoked(store, name, entry, stapling);
            }
            Ok(_) => Error::stapling("The OCSP responder does not know the certificate."),
            Err(error) => error,
        };
        stapling.failures = stapling.failures.saturating_add(1);
        stapling.next = now + schedule::retry_delay(stapling.failures, None);
        let name = name.to_owned();
        (self.report)(&Event::StapleFailed { name, error: failure, retry_at: stapling.next });
    }

    /// The authority revoked the served certificate: nothing is stapled, the responder
    /// is not asked again, and the renewal is due at once. A certificate that this
    /// process obtained waits for its floor, so a responder cannot make us order in a
    /// loop. A name in a retry delay keeps that delay.
    fn revoked(&self, store: &Store, name: &str, entry: &mut Entry, stapling: &mut Stapling) {
        stapling.until = None;
        stapling.next = u64::MAX;
        stapling.revoked = true;
        self.shared.staple(name, None);
        store.clear_staple(name);
        if let (Some(served), None) = (&entry.served, &entry.error) {
            let floor = ari::floor(entry.obtained, served.not_before, served.not_after);
            entry.next_attempt = entry.next_attempt.min(now().max(floor));
        }
        (self.report)(&Event::Revoked { name: name.to_owned() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thread_wakes_for_the_next_question_and_for_the_end_of_the_window() {
        let answer = Answer { status: Status::Good, this_update: 1000, next_update: 2000 };
        let mut stapling = Stapling { failures: 3, ..Stapling::new(empty()) };
        assert_eq!((stapling.wake_at(), stapling.is_stapled(), stapling.word()), (0, false, "-"));
        stapling.accept(&answer, 1100);
        assert_eq!((stapling.wake_at(), stapling.is_stapled()), (1500, true));
        assert_eq!((stapling.word(), stapling.is_revoked()), ("good", false));
        assert_eq!(stapling.failures, 0);
        // A responder that is not asked again: the end of the window still wakes us.
        stapling.next = u64::MAX;
        assert_eq!(stapling.wake_at(), 2000);
        stapling.revoked = true;
        assert_eq!(stapling.word(), "revoked");
    }

    /// A responder for a test of the times: no test here sends its request.
    fn empty() -> Responder {
        use sibuna_acme::{KeyPair, x509};
        let Ok(key) = KeyPair::generate() else { unreachable!("the system has random bytes") };
        let template = x509::Template {
            issuer: "T",
            subject: "T",
            not_after: 10,
            ocsp_url: Some("http://127.0.0.1:1/"),
            ..x509::Template::default()
        };
        let der = x509::write(&template, &key.subject_public_key_info(), &key);
        match der.ok().and_then(|der| Responder::find(&der, &der)) {
            Some(responder) => responder,
            None => unreachable!("the certificate names a responder"),
        }
    }
}
