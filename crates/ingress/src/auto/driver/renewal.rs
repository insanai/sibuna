//! Renewal information (RFC 9773) in the certificate thread: it asks the authority of
//! a served certificate when to renew it, and moves the renewal time (SID 0021).

use std::sync::atomic::Ordering;
use std::time::Duration;

use sibuna_acme::{Error, Request, Response, ari};

use super::authority::Ready;
use super::{Driver, Entry, now};

/// The longest wait for one answer about a renewal.
const ASK_LIMIT: Duration = Duration::from_secs(15);

/// Sends one request of the renewal information to the authority `index`.
fn send(ready: &Ready, index: usize, request: &Request) -> Result<Response, Error> {
    let exchange =
        async { tokio::time::timeout(ASK_LIMIT, ready.at(index).client.send(request)).await };
    match ready.runtime.block_on(exchange) {
        Ok(result) => result,
        Err(_) => Err(Error::unreachable(format!("{}: no answer in time.", request.url))),
    }
}

/// The `renewalInfo` URL of the authority `index`, asked once and then remembered.
/// `Ok(None)`: the authority offers none.
fn endpoint(ready: &mut Ready, index: usize) -> Result<Option<String>, Error> {
    if let Some(known) = &ready.at(index).renewal_info {
        return Ok(known.clone());
    }
    let directory = ready.at(index).directory.clone();
    let response = send(ready, index, &ari::directory_request(&directory))?;
    let found = ari::endpoint(&directory, &response)?;
    ready.at_mut(index).renewal_info = Some(found.clone());
    Ok(found)
}

impl Driver {
    /// Asks the authority of the served certificate of `name` when to renew it, when
    /// the question is due, and moves the renewal time. A failure to ask keeps the last
    /// answer, or else the rule of two thirds, and asks again later. A name in a retry
    /// delay keeps that delay.
    pub(super) fn consult(&self, ready: &mut Ready, name: &str, entry: &mut Entry) {
        let asks = self.shared.options.ari && self.shared.ordering.load(Ordering::Acquire);
        let Some(served) = entry.served.as_ref().filter(|_| asks) else { return };
        let now = now();
        if entry.ari_next > now {
            return;
        }
        let life = (served.not_before, served.not_after);
        let Some(id) = ari::certificate_id(served) else {
            entry.ari_next = u64::MAX;
            return;
        };
        let serial = served.serial.clone();
        let answer = endpoint(ready, entry.issued_by).and_then(|endpoint| match endpoint {
            Some(endpoint) => {
                let response = send(ready, entry.issued_by, &ari::request(&endpoint, &id))?;
                ari::parse(&response).map(Some)
            }
            None => Ok(None),
        });
        match answer {
            Ok(Some(info)) => {
                entry.ari_pick = Some(ari::pick(info.window, &serial));
                entry.ari_next = now + ari::poll_after(info.retry_after, life.0, life.1);
            }
            // An authority without renewal information is not asked again.
            Ok(None) => entry.ari_next = u64::MAX,
            Err(_) => entry.ari_next = now + ari::poll_after(None, life.0, life.1),
        }
        if entry.error.is_none() && entry.ari_pick.is_some() {
            // A certificate that this process obtained is not renewed before its floor,
            // whatever its dates say: an authority cannot make us order in a loop.
            let floor = ari::floor(entry.obtained, life.0, life.1);
            entry.next_attempt = entry.renew_at().max(floor);
            self.publish(name, entry, None);
        }
    }
}
