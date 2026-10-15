//! Pattern tags and sets of them.
//!
//! A tag is a small caller-defined number attached to each pattern (a WAF category, a bot
//! class). Tags run from 0 to `MAX_TAG`, so a set of them is one `u64` and accumulating the
//! tags of a whole field costs one `or` per match.

use std::ops::{BitOr, BitOrAssign};

/// Largest tag a pattern may carry.
pub const MAX_TAG: u8 = 63;

/// A set of tags, one bit per tag: bit `t` is set when tag `t` is present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TagSet {
    /// The bits of the set; bit `t` stands for tag `t`.
    pub bits: u64,
}

impl TagSet {
    /// The set with no tags.
    pub const EMPTY: TagSet = TagSet { bits: 0 };

    /// Returns true when `tag` is in the set. Tags above `MAX_TAG` are never in a set.
    pub fn contains(self, tag: u8) -> bool {
        tag <= MAX_TAG && (self.bits >> tag) & 1 == 1
    }

    /// Returns true when the set has no tags.
    pub fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns the number of tags in the set.
    pub fn tag_count(self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Returns the tags in the set in increasing order.
    pub fn iter(self) -> impl Iterator<Item = u8> {
        (0..=MAX_TAG).filter(move |&tag| self.contains(tag))
    }
}

impl BitOr for TagSet {
    type Output = TagSet;

    fn bitor(self, other: TagSet) -> TagSet {
        TagSet { bits: self.bits | other.bits }
    }
}

impl BitOrAssign for TagSet {
    fn bitor_assign(&mut self, other: TagSet) {
        self.bits |= other.bits;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_set_reports_members_in_order() {
        let set = TagSet { bits: (1 << 3) | (1 << 63) } | TagSet { bits: 1 };
        assert!(set.contains(0) && set.contains(3) && set.contains(63));
        assert!(!set.contains(4) && !set.contains(64) && !set.contains(255));
        assert_eq!(set.iter().collect::<Vec<_>>(), [0, 3, 63]);
        assert_eq!(set.tag_count(), 3);
        assert!(TagSet::EMPTY.is_empty() && !set.is_empty());
    }
}
