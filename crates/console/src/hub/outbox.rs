//! A subscriber's bounded outbox (Zig's `subscription_queue.zig`).
//!
//! The outbox holds at most [`QUEUE_CAPACITY`] frames. When a frame arrives at a full
//! outbox, the topic of the oldest frame is invalidated: its queued frames are removed, a
//! gap notice is reserved for it, and the topic takes no further frames until a new
//! subscription resets it. A gap notice is taken before any frame, so a client never
//! completes a broken snapshot or applies a delta across a gap. A ring gap uses the same
//! barrier ([`Outbox::invalidate`]).
//!
//! Zig kept the frames in a fixed array of 2 KiB slots; here a `VecDeque` grows to the
//! same bound, and each frame owns its text.

use std::collections::VecDeque;

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::subscriptions::{QUEUE_CAPACITY, TOPIC_COUNT};

use super::{Frame, Gap, Item};

/// The frames waiting to be sent to one subscriber, and the gap notices that precede them.
#[derive(Clone, Debug)]
pub struct Outbox {
    frames: VecDeque<Frame>,
    capacity: usize,
    /// Topics invalidated until their next subscription.
    blocked: [bool; TOPIC_COUNT],
    /// Gap notices not yet taken, one per topic.
    gaps: [Option<Gap>; TOPIC_COUNT],
}

impl Default for Outbox {
    fn default() -> Outbox {
        Outbox::with_capacity(QUEUE_CAPACITY)
    }
}

impl Outbox {
    /// Returns an empty outbox of `capacity` frames. Panics when `capacity` is zero, an
    /// invariant of the caller.
    pub fn with_capacity(capacity: usize) -> Outbox {
        assert!(capacity > 0, "an outbox holds at least one frame");
        Outbox {
            frames: VecDeque::new(),
            capacity,
            blocked: [false; TOPIC_COUNT],
            gaps: [None; TOPIC_COUNT],
        }
    }

    /// Queues `frame` and returns the topic this invalidated, if any, so its publisher can
    /// pause: the frame's own topic when it is blocked, or the topic of the oldest frame
    /// when the outbox was full. The caller must queue nothing more for that topic until a
    /// new subscription resets it.
    pub fn offer(&mut self, frame: Frame) -> Option<Topic> {
        let index = frame.topic.index();
        if self.blocked[index] {
            return Some(frame.topic);
        }
        let mut invalidated = None;
        if self.frames.len() == self.capacity
            && let Some(victim) = self.frames.front()
        {
            let (topic, epoch) = (victim.topic, victim.epoch);
            invalidated = Some(topic);
            self.invalidate(topic, epoch, 0);
        }
        if self.blocked[index] {
            if let Some(gap) = self.gaps[index].as_mut() {
                gap.dropped += 1;
            }
            return invalidated;
        }
        self.frames.push_back(frame);
        invalidated
    }

    /// Invalidates `topic` at `epoch`: removes its queued frames and reserves a gap notice
    /// counting them plus `dropped`.
    pub fn invalidate(&mut self, topic: Topic, epoch: u64, dropped: u64) {
        let removed = self.remove(topic);
        self.blocked[topic.index()] = true;
        self.gaps[topic.index()] = Some(Gap { topic, epoch, dropped: dropped + removed });
    }

    /// Removes `topic`'s frames and gap notice and accepts its frames again; a new
    /// subscription epoch begins.
    pub fn reset(&mut self, topic: Topic) {
        self.remove(topic);
        self.blocked[topic.index()] = false;
        self.gaps[topic.index()] = None;
    }

    /// Takes the next item: a gap notice before any frame.
    pub fn pop(&mut self) -> Option<Item> {
        if let Some(gap) = self.gaps.iter_mut().find_map(Option::take) {
            return Some(Item::Gap(gap));
        }
        self.frames.pop_front().map(Item::Frame)
    }

    /// Returns true when an item is waiting.
    pub fn is_ready(&self) -> bool {
        !self.frames.is_empty() || self.gaps.iter().any(Option::is_some)
    }

    /// Removes `topic`'s frames, keeping the order of the others, and returns how many
    /// were removed.
    fn remove(&mut self, topic: Topic) -> u64 {
        let before = self.frames.len();
        self.frames.retain(|frame| frame.topic != topic);
        (before - self.frames.len()) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(topic: Topic, epoch: u64, text: &str) -> Frame {
        Frame { topic, epoch, text: text.to_owned() }
    }

    fn frame_topic(item: Option<Item>) -> Topic {
        match item {
            Some(Item::Frame(frame)) => frame.topic,
            other => panic!("expected a frame, found {other:?}"),
        }
    }

    // Port of subscription_queue.zig "overflow emits a gap before other topics and never
    // completes a broken snapshot".
    #[test]
    fn overflow_emits_a_gap_before_other_topics_and_never_completes_a_broken_snapshot() {
        let mut queue = Outbox::with_capacity(3);
        let stats = frame(Topic::Stats, 1, "s");
        let events = frame(Topic::Events, 2, "e");
        assert_eq!(queue.offer(stats.clone()), None);
        assert_eq!(queue.offer(events.clone()), None);
        assert_eq!(queue.offer(stats.clone()), None);
        assert_eq!(queue.offer(stats.clone()), Some(Topic::Stats));
        match queue.pop() {
            Some(Item::Gap(gap)) => assert_eq!(gap.dropped, 3),
            other => panic!("expected a gap, found {other:?}"),
        }
        assert_eq!(frame_topic(queue.pop()), Topic::Events);
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.offer(stats.clone()), Some(Topic::Stats));
        queue.reset(Topic::Stats);
        assert_eq!(queue.offer(stats.clone()), None);
        assert_eq!(frame_topic(queue.pop()), Topic::Stats);
        for _ in 0..9 {
            assert_eq!(queue.offer(events.clone()), None);
            assert_eq!(queue.offer(stats.clone()), None);
            queue.reset(Topic::Events);
            assert_eq!(frame_topic(queue.pop()), Topic::Stats);
            assert_eq!(queue.pop(), None);
        }
        assert!(!queue.is_ready());
    }
}
