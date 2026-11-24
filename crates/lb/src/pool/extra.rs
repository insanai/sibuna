//! What SID 0019 adds to admission: the servers a request already tried.
//!
//! The state of a server lives in its [`Load`], which a reload keeps for every address.

use std::sync::Arc;

use super::{Load, Target, Ticket};

/// The servers one request has tried. A retry never selects one of them again.
#[derive(Default)]
pub(crate) struct Tried(Vec<Arc<Load>>);

impl Tried {
    /// The servers of `self` and the server of `ticket`.
    pub fn with(&self, ticket: &Ticket) -> Self {
        let mut tried = Vec::with_capacity(self.0.len() + 1);
        tried.extend(self.0.iter().cloned());
        tried.push(Arc::clone(&ticket.load));
        Self(tried)
    }

    /// How many servers were tried.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn holds(&self, load: &Arc<Load>) -> bool {
        self.0.iter().any(|tried| Arc::ptr_eq(tried, load))
    }
}

/// What one reservation asks for beyond the scheduler's choice.
#[derive(Default)]
pub(crate) struct Wish<'a> {
    /// Servers that must not be selected.
    pub tried: Option<&'a Tried>,
}

impl Wish<'_> {
    /// Whether the request may still use `target`.
    pub(super) fn allows(&self, target: &Target) -> bool {
        self.tried.is_none_or(|tried| !tried.holds(&target.load))
    }
}
