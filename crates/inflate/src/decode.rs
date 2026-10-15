//! The hot loop: Huffman-coded literals and matches of fixed and dynamic blocks.
//!
//! Each round refills the bit buffer once and decodes one whole item (a literal, a match
//! with its length and distance, or the end of the block) from it. An item takes at most
//! 15 + 5 + 15 + 13 = 48 bits and a refill leaves at least 56 while eight input bytes
//! remain, so away from the end of the input no item is ever split. Near the end, an item
//! that does not fit in the bits left is not consumed at all, and the next call decodes it
//! again from the start.

use crate::bits::{BitBuffer, Input, low_mask};
use crate::decoder::{Decoder, Flow};
use crate::error::Error;
use crate::huffman::{DistTable, Kind, LitLenTable};
use crate::window::copy_match;

/// One decoded element of a Huffman block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Literal(u8),
    Match { length: usize, distance: usize },
    EndOfBlock,
}

/// The result of decoding one item from the bit buffer: the item and its size in bits, or
/// `None` when the buffer holds too few bits to tell.
type Decoded = Option<(Item, u32)>;

/// Returns "need more bits": an error at the end of the input, `None` otherwise.
#[inline(always)]
fn more_bits(is_last: bool) -> Result<Decoded, Error> {
    if is_last { Err(Error::Truncated) } else { Ok(None) }
}

/// Decodes one item from the start of `bits` without consuming anything.
///
/// Errors come in the order Zig 0.16 and zlib report them: a bit pattern that is no code is
/// [`Error::InvalidCode`] as soon as the bits that decide it are present (or at the end of
/// the input, reading zeros past it); a code that is longer than the remaining input is
/// [`Error::Truncated`] even when its symbol would be reserved.
#[inline(always)]
fn decode_item(
    bits: &BitBuffer,
    litlen: &LitLenTable,
    dist: &DistTable,
    is_last: bool,
) -> Result<Decoded, Error> {
    let (word, count) = (bits.word, bits.count);
    let entry = litlen.lookup(word);
    let mut used = entry.code_len();
    match entry.kind() {
        Kind::Literal if used <= count => {
            return Ok(Some((Item::Literal(entry.value() as u8), used)));
        }
        Kind::Base if used <= count => {}
        Kind::EndOfBlock if used <= count => return Ok(Some((Item::EndOfBlock, used))),
        Kind::Hole if is_last || used <= count => return Err(Error::InvalidCode),
        Kind::Reserved if used <= count => return Err(Error::InvalidCode),
        _ => return more_bits(is_last),
    }
    let extra = entry.extra_bits();
    if used + extra > count {
        return more_bits(is_last);
    }
    let length = entry.value() as usize + ((word >> used) & low_mask(extra)) as usize;
    used += extra;
    let entry = dist.lookup(word >> used);
    let code_len = entry.code_len();
    match entry.kind() {
        Kind::Base if used + code_len <= count => {}
        Kind::Hole if is_last || used + code_len <= count => return Err(Error::InvalidCode),
        Kind::Reserved if used + code_len <= count => return Err(Error::InvalidCode),
        _ => return more_bits(is_last),
    }
    used += code_len;
    let extra = entry.extra_bits();
    if used + extra > count {
        return more_bits(is_last);
    }
    let distance = entry.value() as usize + ((word >> used) & low_mask(extra)) as usize;
    used += extra;
    Ok(Some((Item::Match { length, distance }, used)))
}

impl Decoder {
    /// Decodes the items of a fixed or dynamic Huffman block into the window until the block
    /// ends, the input runs out or the window is full.
    pub(crate) fn step_huffman(
        &mut self,
        fixed: bool,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        let cap = self.output_cap();
        let tables = &*self.tables;
        let (litlen, dist) = if fixed {
            (&tables.fixed_litlen, &tables.fixed_dist)
        } else {
            (&tables.litlen, &tables.dist)
        };
        let window = &mut self.window;
        let buf = &mut window.buf[..];
        let end = cap.min(buf.len());
        let member_start = window.member_start;
        let mut pos = window.pos;
        let mut bits = self.bits;
        // Indexing below stays in bounds: `pos < end <= buf.len()` before a literal is
        // written, `pos + length <= end` before a match is copied, and the distance check
        // keeps `distance <= pos - member_start <= pos` (`member_start <= pos` always holds:
        // it is set to `pos` and both move down together when the window slides).
        let outcome = loop {
            bits.refill(input);
            let (item, used) = match decode_item(&bits, litlen, dist, is_last) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break Ok(Flow::NeedInput),
                Err(error) => break Err(error),
            };
            match item {
                Item::Literal(byte) => {
                    if pos == end {
                        break out_of_room(pos + 1, cap);
                    }
                    buf[pos] = byte;
                    pos += 1;
                }
                Item::Match { length, distance } => {
                    if distance > pos - member_start {
                        break Err(Error::DistanceTooFar);
                    }
                    if pos + length > end {
                        break out_of_room(pos + length, cap);
                    }
                    copy_match(buf, pos, distance, length);
                    pos += length;
                }
                Item::EndOfBlock => {
                    bits.consume(used);
                    break Ok(Flow::Continue);
                }
            }
            bits.consume(used);
        };
        window.pos = pos;
        self.bits = bits;
        if outcome == Ok(Flow::Continue) {
            self.end_block();
        }
        outcome
    }
}

/// Returns the outcome for an item that would end at window position `needed`: beyond the
/// output limit is an error, otherwise the window must be emptied first.
fn out_of_room(needed: usize, cap: usize) -> Result<Flow, Error> {
    if needed > cap { Err(Error::OutputLimit) } else { Ok(Flow::WindowFull) }
}
