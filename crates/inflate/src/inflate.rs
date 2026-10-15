//! DEFLATE block structure (RFC 1951 section 3.2.3 to 3.2.7): block headers, stored blocks
//! and the code lengths of dynamic blocks. The Huffman-coded data itself is in `decode`.
//!
//! Every handler is resumable: it consumes bits only for elements it can read completely,
//! so a call that runs out of input returns [`Flow::NeedInput`] and the next call continues
//! where it stopped.

use crate::bits::{Input, low_mask};
use crate::decoder::{Decoder, Flow, State, need_input};
use crate::error::Error;
use crate::huffman::{Alphabet, Kind};

/// The order in which a dynamic header lists the code length code's lengths.
const CODE_LENGTH_ORDER: [usize; 19] =
    [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Where reading a dynamic block header is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// HLIT, HDIST and HCLEN.
    Counts,
    /// The 3-bit lengths of the code length code.
    CodeLengthLens,
    /// The run-length coded lengths of the literal/length and distance codes.
    Lengths,
}

/// The partly read header of a dynamic block.
pub(crate) struct DynamicHeader {
    stage: Stage,
    litlen_count: usize,
    dist_count: usize,
    code_length_count: usize,
    /// The next length to read in the current stage.
    index: usize,
    code_length_lens: [u8; 19],
    /// Literal/length code lengths followed by distance code lengths.
    lens: [u8; 286 + 30],
}

impl DynamicHeader {
    /// Returns a header at the start of reading.
    pub(crate) fn new() -> Self {
        Self {
            stage: Stage::Counts,
            litlen_count: 0,
            dist_count: 0,
            code_length_count: 0,
            index: 0,
            code_length_lens: [0; 19],
            lens: [0; 286 + 30],
        }
    }
}

impl Decoder {
    /// Reads BFINAL and BTYPE.
    pub(crate) fn step_block_header(
        &mut self,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        let Some(header) = self.bits.take(3, input) else { return need_input(is_last) };
        self.final_block = header & 1 != 0;
        self.state = match header >> 1 {
            0 => {
                self.bits.align_to_byte();
                State::StoredHeader
            }
            1 => State::Huffman { fixed: true },
            2 => {
                *self.dynamic = DynamicHeader::new();
                State::DynamicHeader
            }
            _ => return Err(Error::InvalidBlockType),
        };
        Ok(Flow::Continue)
    }

    /// Reads LEN and NLEN of a stored block.
    pub(crate) fn step_stored_header(
        &mut self,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        let Some(lengths) = self.bits.take(32, input) else { return need_input(is_last) };
        let length = (lengths & 0xffff) as u16;
        if length != !((lengths >> 16) as u16) {
            return Err(Error::StoredLengthMismatch);
        }
        if length == 0 {
            self.end_block();
        } else {
            self.state = State::Stored { remaining: length };
        }
        Ok(Flow::Continue)
    }

    /// Copies the bytes of a stored block: first whole bytes left in the bit buffer, then
    /// straight from the input.
    pub(crate) fn step_stored(
        &mut self,
        remaining: u16,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        let cap = self.output_cap();
        let end = cap.min(self.window.buf.len());
        let mut remaining = usize::from(remaining);
        // Bytes are written only while `pos < end <= buf.len()`, and the bulk copy is at most
        // `end - pos` long.
        while remaining > 0 && self.bits.count >= 8 && self.window.pos < end {
            if let Some(byte) = self.bits.take_byte(input) {
                self.window.buf[self.window.pos] = byte;
                self.window.pos += 1;
                remaining -= 1;
            }
        }
        if self.bits.count < 8 {
            self.bits.clear_lookahead();
            let available = input.rest();
            let count = remaining.min(available.len()).min(end - self.window.pos);
            let pos = self.window.pos;
            self.window.buf[pos..pos + count].copy_from_slice(&available[..count]);
            input.advance(count);
            self.window.pos += count;
            remaining -= count;
        }
        if remaining == 0 {
            self.end_block();
            return Ok(Flow::Continue);
        }
        // `remaining` started as a u16 and only decreased.
        self.state = State::Stored { remaining: remaining as u16 };
        if self.window.pos == end {
            return if end == cap { Err(Error::OutputLimit) } else { Ok(Flow::WindowFull) };
        }
        need_input(is_last)
    }

    /// Reads a dynamic block header and builds its tables.
    pub(crate) fn step_dynamic_header(
        &mut self,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        loop {
            let header = &mut *self.dynamic;
            match header.stage {
                Stage::Counts => {
                    let Some(counts) = self.bits.take(14, input) else {
                        return need_input(is_last);
                    };
                    header.litlen_count = 257 + (counts & 31) as usize;
                    header.dist_count = 1 + ((counts >> 5) & 31) as usize;
                    header.code_length_count = 4 + (counts >> 10) as usize;
                    if header.litlen_count > 286 || header.dist_count > 30 {
                        return Err(Error::InvalidDynamicHeader);
                    }
                    header.stage = Stage::CodeLengthLens;
                    header.index = 0;
                }
                Stage::CodeLengthLens => {
                    while header.index < header.code_length_count {
                        let Some(len) = self.bits.take(3, input) else {
                            return need_input(is_last);
                        };
                        // `index < code_length_count <= 19`, and the order lists symbols 0-18.
                        header.code_length_lens[CODE_LENGTH_ORDER[header.index]] = len as u8;
                        header.index += 1;
                    }
                    self.tables
                        .code_length
                        .build(&header.code_length_lens, Alphabet::CodeLength)?;
                    header.stage = Stage::Lengths;
                    header.index = 0;
                }
                Stage::Lengths => return self.read_code_lengths(input, is_last),
            }
        }
    }

    /// Reads the run-length coded code lengths, then builds the literal/length and distance
    /// tables and starts the block's data.
    fn read_code_lengths(&mut self, input: &mut Input<'_>, is_last: bool) -> Result<Flow, Error> {
        let header = &mut *self.dynamic;
        let total = header.litlen_count + header.dist_count;
        while header.index < total {
            self.bits.refill(input);
            let (word, count) = (self.bits.word, self.bits.count);
            let entry = self.tables.code_length.lookup(word);
            let len = entry.code_len();
            match entry.kind() {
                Kind::Literal if len <= count => {}
                Kind::Hole if is_last || len <= count => return Err(Error::InvalidCode),
                _ => return need_input(is_last),
            }
            let symbol = entry.value();
            let (extra, base) = match symbol {
                0..=15 => (0, 1),
                16 => (2, 3),
                17 => (3, 3),
                _ => (7, 11),
            };
            if len + extra > count {
                return need_input(is_last);
            }
            let repeat = base + ((word >> len) & low_mask(extra)) as usize;
            self.bits.consume(len + extra);
            // `index < total <= lens.len()`, `index - 1` is guarded by the zero check, and the
            // run is checked against `total` before it is written.
            let index = header.index;
            let fill = match symbol {
                0..=15 => symbol as u8,
                16 if index == 0 => return Err(Error::InvalidDynamicHeader),
                16 => header.lens[index - 1],
                _ => 0,
            };
            if index + repeat > total {
                return Err(Error::InvalidDynamicHeader);
            }
            header.lens[index..index + repeat].fill(fill);
            header.index += repeat;
        }
        let (litlen_lens, rest) = header.lens.split_at(header.litlen_count);
        self.tables.litlen.build(litlen_lens, Alphabet::LitLen)?;
        self.tables.dist.build(&rest[..header.dist_count], Alphabet::Distance)?;
        self.state = State::Huffman { fixed: false };
        Ok(Flow::Continue)
    }
}
