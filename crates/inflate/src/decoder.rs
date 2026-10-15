//! The streaming decoder: the public [`Decoder`], its configuration and the loop that moves
//! bytes between the caller, the state machine and the window.

use std::convert::Infallible;
use std::io;

use crate::bits::{BitBuffer, Input};
use crate::crc32::Crc32;
use crate::error::Error;
use crate::gzip::HeaderParser;
use crate::huffman::{self, CodeLengthTable, DistTable, LitLenTable};
use crate::inflate::DynamicHeader;
use crate::window::Window;

/// The container around the DEFLATE data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// A bare DEFLATE stream (RFC 1951) with no header or checksum.
    Raw,
    /// One or more gzip members (RFC 1952), each with a header and a CRC-32 and size footer.
    Gzip,
}

/// Bounds on the work one stream may cause. Exceeding one is an error, never a panic.
///
/// The default allows 1 GiB of input, 1 GiB of output and one gzip member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The most compressed bytes the stream may consume ([`Error::InputLimit`]).
    pub max_input_bytes: u64,
    /// The most bytes the stream may decompress to ([`Error::OutputLimit`]).
    pub max_output_bytes: u64,
    /// The most gzip members to decode; zero acts as one. With the default of one, a second
    /// member is trailing data, exactly as Sibuna's Zig GeoIP loader treated it. RFC 1952
    /// allows any number of concatenated members (as `cat a.gz b.gz` produces); raise the
    /// bound to accept them. Raw streams ignore this field.
    pub max_members: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_input_bytes: 1 << 30, max_output_bytes: 1 << 30, max_members: 1 }
    }
}

impl Limits {
    /// No bounds at all. Use it only for trusted input.
    pub const UNBOUNDED: Limits =
        Limits { max_input_bytes: u64::MAX, max_output_bytes: u64::MAX, max_members: u32::MAX };
}

/// Why a call to [`Decoder::decompress`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// The decoder used all input it was given and needs more to continue.
    NeedInput,
    /// The output buffer is full; call again with more room (and the unconsumed input).
    OutputFull,
    /// The stream is complete and all of its output has been written. Input bytes after the
    /// stream are not consumed.
    Done,
}

/// What one call to the decoder did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Progress {
    /// How many bytes of the input the call consumed. The caller passes the rest again.
    pub consumed: usize,
    /// How many bytes the call wrote to the output.
    pub written: usize,
    /// Why the call returned.
    pub status: Status,
}

/// Where the state machine is in the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    GzipHeader,
    BlockHeader,
    StoredHeader,
    Stored { remaining: u16 },
    DynamicHeader,
    Huffman { fixed: bool },
    GzipFooter,
    MemberEnd,
    Done,
}

/// What a state handler asks the driving loop to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// The state changed; run the next handler.
    Continue,
    /// The input is used up.
    NeedInput,
    /// The window has no room for the next item; deliver pending bytes and slide.
    WindowFull,
}

/// Returns the flow for a handler that needs more input than it has: an error at the end
/// of the input, a request for more otherwise.
pub(crate) fn need_input(is_last: bool) -> Result<Flow, Error> {
    if is_last { Err(Error::Truncated) } else { Ok(Flow::NeedInput) }
}

/// The Huffman tables a decoder owns: the current dynamic block's, and the fixed ones built
/// once.
pub(crate) struct Tables {
    pub(crate) litlen: LitLenTable,
    pub(crate) dist: DistTable,
    pub(crate) fixed_litlen: LitLenTable,
    pub(crate) fixed_dist: DistTable,
    pub(crate) code_length: CodeLengthTable,
}

/// A streaming DEFLATE or gzip decoder with a 32 KiB history window.
///
/// The decoder owns about 160 KiB (window and tables), allocated once in [`Decoder::new`];
/// decoding allocates nothing more. Feed it input in chunks of any size, from one byte up,
/// and take the output in chunks of any size:
///
/// ```
/// use sibuna_inflate::{Decoder, Format, Limits, Status};
///
/// # fn main() -> Result<(), sibuna_inflate::Error> {
/// // "Hello world\n" as a gzip member with a fixed Huffman block.
/// let gz = [
///     0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0xf3, 0x48, 0xcd, 0xc9,
///     0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00, 0xd5, 0xe0, 0x39, 0xb7,
///     0x0c, 0x00, 0x00, 0x00,
/// ];
/// let mut decoder = Decoder::new(Format::Gzip, Limits::default());
/// let mut input = &gz[..];
/// let mut text = Vec::new();
/// let mut buffer = [0u8; 5];
/// loop {
///     let progress = decoder.decompress(input, true, &mut buffer)?;
///     input = &input[progress.consumed..];
///     text.extend_from_slice(&buffer[..progress.written]);
///     if progress.status == Status::Done {
///         break;
///     }
/// }
/// assert_eq!(text, b"Hello world\n");
/// # Ok(())
/// # }
/// ```
pub struct Decoder {
    pub(crate) format: Format,
    pub(crate) limits: Limits,
    pub(crate) bits: BitBuffer,
    pub(crate) state: State,
    /// The first error; a failed decoder keeps returning it until reset.
    failed: Option<Error>,
    /// Whether the current block is the last of its stream.
    pub(crate) final_block: bool,
    pub(crate) tables: Box<Tables>,
    pub(crate) dynamic: Box<DynamicHeader>,
    pub(crate) header: HeaderParser,
    pub(crate) footer: [u8; 8],
    pub(crate) footer_len: usize,
    pub(crate) window: Window,
    /// The CRC-32 and size (modulo 2^32) of the current member's output.
    pub(crate) crc: Crc32,
    pub(crate) member_size: u32,
    input_count: u64,
    output_count: u64,
    pub(crate) member_count: u32,
}

impl Decoder {
    /// Returns a decoder for one stream of `format`, bounded by `limits`.
    pub fn new(format: Format, limits: Limits) -> Self {
        let mut tables = Box::new(Tables {
            litlen: LitLenTable::new(),
            dist: DistTable::new(),
            fixed_litlen: LitLenTable::new(),
            fixed_dist: DistTable::new(),
            code_length: CodeLengthTable::new(),
        });
        let Tables { fixed_litlen, fixed_dist, .. } = &mut *tables;
        huffman::build_fixed(fixed_litlen, fixed_dist);
        let mut decoder = Self {
            format,
            limits,
            bits: BitBuffer::default(),
            state: State::BlockHeader,
            failed: None,
            final_block: false,
            tables,
            dynamic: Box::new(DynamicHeader::new()),
            header: HeaderParser::new(),
            footer: [0; 8],
            footer_len: 0,
            window: Window::new(),
            crc: Crc32::new(),
            member_size: 0,
            input_count: 0,
            output_count: 0,
            member_count: 0,
        };
        decoder.begin_member();
        decoder
    }

    /// Prepares the decoder for a new stream with the same format and limits, keeping its
    /// buffers.
    pub fn reset(&mut self) {
        self.reset_with(self.limits);
    }

    /// Prepares the decoder for a new stream with the same format and new `limits`, keeping
    /// its buffers. A server can keep one decoder per thread this way and still give each
    /// stream its own bounds.
    pub fn reset_with(&mut self, limits: Limits) {
        self.limits = limits;
        self.bits = BitBuffer::default();
        self.failed = None;
        self.window.clear();
        self.input_count = 0;
        self.output_count = 0;
        self.member_count = 0;
        self.begin_member();
    }

    /// Starts a gzip member, or the raw stream.
    pub(crate) fn begin_member(&mut self) {
        self.state = match self.format {
            Format::Raw => State::BlockHeader,
            Format::Gzip => State::GzipHeader,
        };
        self.final_block = false;
        self.header = HeaderParser::new();
        self.footer_len = 0;
        self.crc = Crc32::new();
        self.member_size = 0;
        self.window.start_member();
    }

    /// Returns whether the stream is complete and all of its output was handed out.
    pub fn is_done(&self) -> bool {
        self.state == State::Done && self.window.pending().is_empty()
    }

    /// Returns how many compressed bytes the decoder has consumed.
    pub fn input_byte_count(&self) -> u64 {
        self.input_count
    }

    /// Returns how many bytes the decoder has decompressed, including bytes it holds that
    /// the caller has not taken yet.
    pub fn output_byte_count(&self) -> u64 {
        self.output_count
    }

    /// Returns how many gzip members the decoder has completed and verified.
    pub fn member_count(&self) -> u32 {
        self.member_count
    }

    /// Decompresses from `input` into `output`.
    ///
    /// Borrows `input` and `output` for the call only. `is_last` says that `input` holds
    /// everything that is left of the stream; then a stream that ends early is
    /// [`Error::Truncated`] instead of [`Status::NeedInput`]. Returns how much was consumed
    /// and written and why the call stopped. Fails on corrupt data and exceeded limits; after
    /// an error, every later call returns the same error until [`Decoder::reset`].
    pub fn decompress(
        &mut self,
        input: &[u8],
        is_last: bool,
        output: &mut [u8],
    ) -> Result<Progress, Error> {
        let mut written = 0;
        let result = self.run(input, is_last, |pending| {
            // `written <= output.len()` because each round copies at most the room left.
            let count = pending.len().min(output.len() - written);
            output[written..written + count].copy_from_slice(&pending[..count]);
            written += count;
            Ok::<usize, Infallible>(count)
        });
        result.map_err(|failure| match failure {
            Failure::Decode(error) => error,
            Failure::Sink(never) => match never {},
        })
    }

    /// Decompresses all of `input` that it can and writes the output to `sink`.
    ///
    /// Like [`Decoder::decompress`], but the output never fills up, so the status is
    /// [`Status::NeedInput`] or [`Status::Done`]. Decoding errors come back as
    /// [`io::ErrorKind::InvalidData`] wrapping an [`Error`] (see [`io::Error::get_ref`]);
    /// errors of the sink come back unchanged.
    pub fn decompress_to<W: io::Write + ?Sized>(
        &mut self,
        input: &[u8],
        is_last: bool,
        sink: &mut W,
    ) -> io::Result<Progress> {
        let result =
            self.run(input, is_last, |pending| sink.write_all(pending).map(|()| pending.len()));
        result.map_err(|failure| match failure {
            Failure::Decode(error) => io::Error::new(io::ErrorKind::InvalidData, error),
            Failure::Sink(error) => error,
        })
    }

    /// Decompresses all of `input` and appends the output to `output`, growing it fallibly.
    pub(crate) fn decompress_into_vec(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<Progress, Error> {
        let result = self.run(input, true, |pending| {
            output.try_reserve(pending.len()).map_err(|_| Error::OutOfMemory)?;
            output.extend_from_slice(pending);
            Ok(pending.len())
        });
        result.map_err(|failure| match failure {
            Failure::Decode(error) | Failure::Sink(error) => error,
        })
    }

    /// Drives the state machine over `input`, handing decoded bytes to `emit`, which returns
    /// how many it accepted. Accepting fewer than offered means the output is full.
    fn run<E>(
        &mut self,
        input: &[u8],
        is_last: bool,
        mut emit: impl FnMut(&[u8]) -> Result<usize, E>,
    ) -> Result<Progress, Failure<E>> {
        if let Some(error) = self.failed {
            return Err(Failure::Decode(error));
        }
        let allowed = self.limits.max_input_bytes.saturating_sub(self.input_count);
        let allowed = usize::try_from(allowed).unwrap_or(usize::MAX).min(input.len());
        let limited = allowed < input.len();
        let mut input = Input::new(&input[..allowed]);
        let mut written = 0;
        let status = loop {
            let pending = self.window.pending();
            if !pending.is_empty() {
                let offered = pending.len();
                let accepted = emit(pending).map_err(Failure::Sink)?;
                self.window.mark_delivered(accepted);
                written += accepted;
                if accepted < offered {
                    break Status::OutputFull;
                }
            }
            if self.state == State::Done {
                break Status::Done;
            }
            self.window.make_room();
            let before = self.window.pos;
            let flow = self.step(&mut input, is_last && !limited);
            self.account(before);
            match flow {
                Ok(Flow::Continue | Flow::WindowFull) => {}
                Ok(Flow::NeedInput) if limited => return Err(self.fail(Error::InputLimit)),
                Ok(Flow::NeedInput) => break Status::NeedInput,
                Err(error) => return Err(self.fail(error)),
            }
        };
        if status != Status::NeedInput {
            self.bits.give_back(&mut input);
        }
        let consumed = input.taken();
        self.input_count += consumed as u64;
        Ok(Progress { consumed, written, status })
    }

    /// Records `error` as the decoder's final state.
    fn fail<E>(&mut self, error: Error) -> Failure<E> {
        self.failed = Some(error);
        Failure::Decode(error)
    }

    /// Runs the handler of the current state once.
    fn step(&mut self, input: &mut Input<'_>, is_last: bool) -> Result<Flow, Error> {
        match self.state {
            State::GzipHeader => self.step_gzip_header(input, is_last),
            State::BlockHeader => self.step_block_header(input, is_last),
            State::StoredHeader => self.step_stored_header(input, is_last),
            State::Stored { remaining } => self.step_stored(remaining, input, is_last),
            State::DynamicHeader => self.step_dynamic_header(input, is_last),
            State::Huffman { fixed } => self.step_huffman(fixed, input, is_last),
            State::GzipFooter => self.step_gzip_footer(input, is_last),
            State::MemberEnd => self.step_member_end(input, is_last),
            State::Done => Ok(Flow::Continue),
        }
    }

    /// Adds the bytes a handler decoded since window position `before` to the checksum and
    /// the counters.
    fn account(&mut self, before: usize) {
        // Handlers only append to the window (it slides in `make_room`, before them), so
        // `before <= pos`.
        let produced = &self.window.buf[before..self.window.pos];
        if self.format == Format::Gzip {
            self.crc.update(produced);
            self.member_size = self.member_size.wrapping_add(produced.len() as u32);
        }
        self.output_count += produced.len() as u64;
    }

    /// Returns the window position up to which the output limit allows decoding.
    pub(crate) fn output_cap(&self) -> usize {
        let allowed = self.limits.max_output_bytes.saturating_sub(self.output_count);
        self.window.pos.saturating_add(usize::try_from(allowed).unwrap_or(usize::MAX))
    }

    /// Ends the current block: the next block header, or the end of the stream.
    pub(crate) fn end_block(&mut self) {
        if !self.final_block {
            self.state = State::BlockHeader;
            return;
        }
        self.bits.align_to_byte();
        self.state = match self.format {
            Format::Raw => State::Done,
            Format::Gzip => State::GzipFooter,
        };
    }
}

/// An error of the run loop: from decoding, or from the output sink.
enum Failure<E> {
    Decode(Error),
    Sink(E),
}
