//! A table of records addressed by index and generation.
//!
//! A readiness event names a record by its index. The record may have been closed and
//! its index given to a new one between the event and its handling. The generation of a
//! slot grows each time it is vacated, so a stale event finds no record.

/// Records of one kind, owned by one worker.
#[derive(Debug)]
pub struct Slab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    live: usize,
}

#[derive(Debug)]
struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Slab<T> {
    /// An empty table.
    pub fn new() -> Self {
        Self { slots: Vec::new(), free: Vec::new(), live: 0 }
    }

    /// Stores `value` and returns its index and generation.
    pub fn insert(&mut self, value: T) -> (u32, u32) {
        self.live += 1;
        if let Some(index) = self.free.pop()
            && let Some(slot) = self.slots.get_mut(index as usize)
        {
            slot.value = Some(value);
            return (index, slot.generation);
        }
        self.slots.push(Slot { generation: 0, value: Some(value) });
        (self.slots.len() as u32 - 1, 0)
    }

    /// The record at `index`, when it still is the one `generation` named.
    pub fn current(&mut self, index: u32, generation: u32) -> Option<&mut T> {
        let slot = self.slots.get_mut(index as usize)?;
        if slot.generation == generation { slot.value.as_mut() } else { None }
    }

    /// The record at `index`.
    pub fn at(&mut self, index: u32) -> Option<&mut T> {
        self.slots.get_mut(index as usize)?.value.as_mut()
    }

    /// The generation of the slot at `index`.
    pub fn generation(&self, index: u32) -> u32 {
        self.slots.get(index as usize).map_or(0, |slot| slot.generation)
    }

    /// Removes and returns the record at `index`.
    pub fn remove(&mut self, index: u32) -> Option<T> {
        let slot = self.slots.get_mut(index as usize)?;
        let value = slot.value.take()?;
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(index);
        self.live -= 1;
        Some(value)
    }

    /// The number of records.
    pub fn len(&self) -> usize {
        self.live
    }

    /// True when the table holds no record.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// The indices of all records.
    pub fn indices(&self) -> Vec<u32> {
        let live = self.slots.iter().enumerate().filter(|(_, slot)| slot.value.is_some());
        live.map(|(index, _)| index as u32).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reused_index_does_not_answer_to_its_old_generation() {
        let mut slab = Slab::new();
        let (first, generation) = slab.insert("a");
        assert_eq!(slab.current(first, generation), Some(&mut "a"));
        assert_eq!(slab.remove(first), Some("a"));
        assert_eq!(slab.remove(first), None);
        let (second, next) = slab.insert("b");
        assert_eq!((second, slab.len()), (first, 1));
        assert!(slab.current(first, generation).is_none());
        assert_eq!(slab.current(second, next), Some(&mut "b"));
        assert_eq!(slab.indices(), [second]);
    }
}
