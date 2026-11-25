//! The store in memory: the executable form of the Lean model of SID 0028
//! (`docs/sid/assets/database-authority.lean`). The history is a list, the head is its
//! length, and a commit appends when the expected head is the head.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::error::Error;
use crate::store::{
    Draft, Entry, Head, MAX_HISTORY, MAX_NODES, NodeReport, Revision, Store, Woken,
};

#[derive(Default)]
struct Inner {
    history: Vec<Revision>,
    nodes: BTreeMap<String, NodeReport>,
    unavailable: bool,
    announced: bool,
}

/// A store in memory. Clones share the revisions, as connections share a database.
#[derive(Clone, Default)]
pub struct MemoryStore {
    shared: Arc<(Mutex<Inner>, Condvar)>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    /// Makes every operation fail as an unreachable database does, or succeed again.
    /// The revisions stay.
    pub fn set_available(&self, available: bool) {
        self.locked().unavailable = !available;
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.shared.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The state of a store that can be asked.
    fn reachable(&self) -> Result<std::sync::MutexGuard<'_, Inner>, Error> {
        let inner = self.locked();
        if inner.unavailable {
            return Err(Error::Unavailable("the store in memory was set unavailable".to_owned()));
        }
        Ok(inner)
    }
}

impl Store for MemoryStore {
    fn head(&mut self) -> Result<Head, Error> {
        let inner = self.reachable()?;
        Ok(inner.history.last().map_or_else(Head::default, |newest| Head {
            revision: newest.entry.number,
            digest: newest.entry.digest.clone(),
        }))
    }

    fn revision(&mut self, number: u64) -> Result<Revision, Error> {
        let inner = self.reachable()?;
        let index = usize::try_from(number).ok().and_then(|number| number.checked_sub(1));
        let found = index.and_then(|index| inner.history.get(index));
        let revision = found.cloned().ok_or(Error::Unknown(number))?;
        revision.verify(number)?;
        Ok(revision)
    }

    fn commit(&mut self, expected: u64, draft: &Draft<'_>) -> Result<u64, Error> {
        draft.check()?;
        let mut inner = self.reachable()?;
        let found = inner.history.len() as u64;
        if expected != found {
            return Err(Error::Conflict { expected, found });
        }
        inner.history.push(Revision::from_draft(found + 1, draft));
        inner.announced = true;
        self.shared.1.notify_all();
        Ok(found + 1)
    }

    fn history(&mut self, limit: usize) -> Result<Vec<Entry>, Error> {
        let inner = self.reachable()?;
        let newest_first = inner.history.iter().rev().take(limit.min(MAX_HISTORY));
        Ok(newest_first.map(|revision| revision.entry.clone()).collect())
    }

    fn report(&mut self, report: &NodeReport) -> Result<(), Error> {
        self.reachable()?.nodes.insert(report.node.clone(), report.clone());
        Ok(())
    }

    fn nodes(&mut self) -> Result<Vec<NodeReport>, Error> {
        Ok(self.reachable()?.nodes.values().take(MAX_NODES).cloned().collect())
    }

    fn wait(&mut self, timeout: Duration) -> Woken {
        let (lock, announce) = &*self.shared;
        let inner = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let waited = announce.wait_timeout_while(inner, timeout, |inner| !inner.announced);
        let (mut inner, _) = waited.unwrap_or_else(PoisonError::into_inner);
        if std::mem::take(&mut inner.announced) { Woken::Notified } else { Woken::TimedOut }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Origin;

    fn draft(document: &str) -> Draft<'_> {
        Draft {
            document,
            source: document.as_bytes(),
            source_name: "edge.json",
            origin: Origin::Apply,
            author: "op@host",
            note: "",
            now: 1,
        }
    }

    #[test]
    fn a_commit_appends_when_the_expected_head_is_the_head() {
        let mut store = MemoryStore::new();
        assert_eq!(store.head().unwrap(), Head::default());
        assert_eq!(store.commit(0, &draft("{\"a\":1}")), Ok(1));
        // The lemma `second_commit_conflicts`: a second writer that saw head 0 fails.
        let conflict = store.commit(0, &draft("{\"a\":2}")).unwrap_err();
        assert_eq!(conflict, Error::Conflict { expected: 0, found: 1 });
        assert_eq!(store.commit(1, &draft("{\"a\":3}")), Ok(2));
        // The lemma `commit_keeps`: revision 1 reads as before.
        assert_eq!(store.revision(1).unwrap().document, "{\"a\":1}");
        assert_eq!(store.revision(2).unwrap().document, "{\"a\":3}");
        assert_eq!(store.head().unwrap().revision, 2);
        // The lemmas `read_complete` and `read_beyond`.
        assert_eq!(store.revision(0).unwrap_err(), Error::Unknown(0));
        assert_eq!(store.revision(3).unwrap_err(), Error::Unknown(3));
        let numbers: Vec<u64> = store.history(10).unwrap().iter().map(|e| e.number).collect();
        assert_eq!(numbers, [2, 1]);
        assert_eq!(store.history(1).unwrap().len(), 1);
    }

    #[test]
    fn an_unavailable_store_answers_nothing_and_keeps_its_revisions() {
        let mut store = MemoryStore::new();
        store.commit(0, &draft("{}")).unwrap();
        store.set_available(false);
        assert!(store.head().unwrap_err().is_unavailable());
        assert!(store.commit(1, &draft("{}")).unwrap_err().is_unavailable());
        store.set_available(true);
        assert_eq!(store.head().unwrap().revision, 1);
    }

    #[test]
    fn a_commit_wakes_a_waiter_and_reports_replace_each_other() {
        let mut store = MemoryStore::new();
        assert_eq!(store.wait(Duration::from_millis(10)), Woken::TimedOut);
        let mut writer = store.clone();
        let commit = std::thread::spawn(move || writer.commit(0, &draft("{}")));
        assert_eq!(store.wait(Duration::from_secs(10)), Woken::Notified);
        assert_eq!(commit.join().unwrap(), Ok(1));
        let report = |applied| NodeReport { node: "a".into(), applied, ..NodeReport::default() };
        store.report(&report(1)).unwrap();
        store.report(&report(2)).unwrap();
        assert_eq!(store.nodes().unwrap(), [report(2)]);
    }
}
