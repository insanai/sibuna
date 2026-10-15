//! A bounded QR code encoder for authenticator enrollment: Model 2, version 6, error
//! correction level L, byte mode, mask 0. A 134-byte `otpauth` URI fits; the test vectors
//! come from Project Nayuki's independent encoder with the same parameters.

use std::fmt::{self, Write as _};

use sibuna_html::write_value;

use crate::render::Html;
use crate::wipe::wipe_bytes;

/// Modules per side.
pub const SIZE: usize = 41;
/// The longest input, in bytes.
pub const MAX_BYTES: usize = 134;
const DATA_BYTES: usize = 136;
const CODEWORDS: usize = 172;
const CORRECTION_BYTES: usize = 18;
/// Data codewords per block; version 6-L has two blocks.
const BLOCK_BYTES: usize = 68;

/// The input exceeds [`MAX_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLarge;

impl fmt::Display for TooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the text exceeds the QR code's 134 bytes")
    }
}

impl std::error::Error for TooLarge {}

/// An encoded symbol. It encodes a secret, so dropping it erases the modules.
pub struct Qr {
    pixels: [bool; SIZE * SIZE],
    fixed: [bool; SIZE * SIZE],
}

impl Drop for Qr {
    fn drop(&mut self) {
        self.pixels.fill(false);
        std::hint::black_box(&self.pixels);
    }
}

fn bit(value: u32, index: usize) -> bool {
    (value >> index) & 1 != 0
}

impl Qr {
    fn function(&mut self, x: usize, y: usize, dark: bool) {
        self.pixels[y * SIZE + x] = dark;
        self.fixed[y * SIZE + x] = true;
    }

    fn finder(&mut self, center_x: i32, center_y: i32) {
        for dy in -4..=4_i32 {
            for dx in -4..=4_i32 {
                let (x, y) = (center_x + dx, center_y + dy);
                let Ok(x) = usize::try_from(x) else { continue };
                let Ok(y) = usize::try_from(y) else { continue };
                if x >= SIZE || y >= SIZE {
                    continue;
                }
                let distance = dx.abs().max(dy.abs());
                self.function(x, y, distance != 2 && distance != 4);
            }
        }
    }

    fn patterns(&mut self) {
        for i in 0..SIZE {
            self.function(6, i, i % 2 == 0);
            self.function(i, 6, i % 2 == 0);
        }
        let far = SIZE as i32 - 4;
        self.finder(3, 3);
        self.finder(far, 3);
        self.finder(3, far);
        // Version 6 alignment centres are 6 and 34; the other three overlap finders.
        for y in 0..5 {
            for x in 0..5 {
                let inner = (1..=3).contains(&x) && (1..=3).contains(&y);
                self.function(32 + x, 32 + y, !inner || (x == 2 && y == 2));
            }
        }
        // The BCH-protected format bits for level L and mask 0, with the format mask.
        let format: u32 = 0x77c4;
        for i in 0..6 {
            self.function(8, i, bit(format, i));
        }
        self.function(8, 7, bit(format, 6));
        self.function(8, 8, bit(format, 7));
        self.function(7, 8, bit(format, 8));
        for i in 9..15 {
            self.function(14 - i, 8, bit(format, i));
        }
        for i in 0..8 {
            self.function(SIZE - 1 - i, 8, bit(format, i));
        }
        for i in 8..15 {
            self.function(8, SIZE - 15 + i, bit(format, i));
        }
        self.function(8, SIZE - 8, true);
    }

    /// Places the codewords in the zigzag order and applies mask 0.
    fn place(&mut self, bytes: &[u8; CODEWORDS]) {
        let mut index = 0;
        let mut right = SIZE - 1;
        loop {
            if right == 6 {
                right = 5;
            }
            for vertical in 0..SIZE {
                let y = if (right + 1) & 2 == 0 { SIZE - 1 - vertical } else { vertical };
                for x in [right, right - 1] {
                    if self.fixed[y * SIZE + x] {
                        continue;
                    }
                    let value = bytes
                        .get(index / 8)
                        .is_some_and(|byte| bit(u32::from(*byte), 7 - index % 8));
                    self.pixels[y * SIZE + x] = value != ((x + y) % 2 == 0);
                    index += 1;
                }
            }
            if right < 3 {
                break;
            }
            right -= 2;
        }
        debug_assert_eq!(index, CODEWORDS * 8 + 7);
    }

    /// Returns true when the module at column `x`, row `y` is dark.
    #[cfg(test)]
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        x < SIZE && y < SIZE && self.pixels[y * SIZE + x]
    }

    /// Draws the symbol as an SVG image with a four-module quiet zone.
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn svg(&self, out: &mut Html<'_>) -> fmt::Result {
        out.write_str(
            "<svg class=\"sb-qr\" viewBox=\"0 0 49 49\" role=\"img\" \
             aria-label=\"Authenticator enrollment QR code\" shape-rendering=\"crispEdges\">\
             <rect width=\"49\" height=\"49\" fill=\"white\"/><path fill=\"black\" d=\"",
        )?;
        for (index, dark) in self.pixels.iter().enumerate() {
            if *dark {
                out.write_str("M")?;
                write_value(out, &(index % SIZE + 4))?;
                out.write_str(" ")?;
                write_value(out, &(index / SIZE + 4))?;
                out.write_str("h1v1h-1z")?;
            }
        }
        out.write_str("\"/></svg>")
    }
}

/// Encodes `input` in byte mode.
///
/// # Errors
///
/// [`TooLarge`] for more than [`MAX_BYTES`] bytes.
pub fn encode(input: &[u8]) -> Result<Qr, TooLarge> {
    let length = u8::try_from(input.len()).map_err(|_| TooLarge)?;
    if input.len() > MAX_BYTES {
        return Err(TooLarge);
    }
    let mut data = [0u8; DATA_BYTES];
    let mut count = 0;
    append(&mut data, &mut count, 4, 4);
    append(&mut data, &mut count, length, 8);
    for byte in input {
        append(&mut data, &mut count, *byte, 8);
    }
    append(&mut data, &mut count, 0, 4);
    let mut pad = 0xec;
    for byte in data.iter_mut().skip(count.div_ceil(8)) {
        *byte = pad;
        pad ^= 0xfd;
    }
    let mut words = [0u8; CODEWORDS];
    let divisor = generator();
    for (block, bytes) in data.as_chunks::<BLOCK_BYTES>().0.iter().enumerate() {
        for (index, byte) in bytes.iter().enumerate() {
            words[index * 2 + block] = *byte;
        }
        for (index, byte) in remainder(bytes, &divisor).iter().enumerate() {
            words[DATA_BYTES + index * 2 + block] = *byte;
        }
    }
    let mut qr = Qr { pixels: [false; SIZE * SIZE], fixed: [false; SIZE * SIZE] };
    qr.patterns();
    qr.place(&words);
    wipe_bytes(&mut data);
    wipe_bytes(&mut words);
    Ok(qr)
}

/// Appends the low `bits` bits of `value`, most significant first.
fn append(data: &mut [u8; DATA_BYTES], count: &mut usize, value: u8, bits: usize) {
    for index in 0..bits {
        if bit(u32::from(value), bits - 1 - index)
            && let Some(byte) = data.get_mut(*count / 8)
        {
            *byte |= 1 << (7 - *count % 8);
        }
        *count += 1;
    }
}

/// Multiplies in GF(256) with the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
fn multiply(left: u8, right: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..8 {
        let high = result >> 7;
        result = (result << 1) ^ (high * 0x1d);
        if bit(u32::from(right), 7 - i) {
            result ^= left;
        }
    }
    result
}

/// Returns the Reed-Solomon generator polynomial for [`CORRECTION_BYTES`] bytes.
fn generator() -> [u8; CORRECTION_BYTES] {
    let mut polynomial = [0u8; CORRECTION_BYTES];
    polynomial[CORRECTION_BYTES - 1] = 1;
    let mut root: u8 = 1;
    for _ in 0..CORRECTION_BYTES {
        for index in 0..CORRECTION_BYTES {
            polynomial[index] = multiply(polynomial[index], root);
            if index + 1 < CORRECTION_BYTES {
                polynomial[index] ^= polynomial[index + 1];
            }
        }
        root = multiply(root, 2);
    }
    polynomial
}

/// Returns the error correction bytes of `input`.
fn remainder(input: &[u8], divisor: &[u8; CORRECTION_BYTES]) -> [u8; CORRECTION_BYTES] {
    let mut result = [0u8; CORRECTION_BYTES];
    for byte in input {
        let factor = byte ^ result[0];
        result.copy_within(1.., 0);
        result[CORRECTION_BYTES - 1] = 0;
        for (coefficient, multiplier) in result.iter_mut().zip(divisor) {
            *coefficient ^= multiply(*multiplier, factor);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix_digest(input: &[u8]) -> String {
        let qr = encode(input).unwrap();
        let mut bytes = Vec::with_capacity(SIZE * SIZE);
        for y in 0..SIZE {
            for x in 0..SIZE {
                bytes.push(u8::from(qr.is_dark(x, y)));
            }
        }
        let hash = sibuna_crypto::sha256::Sha256::digest(&bytes);
        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Vectors from Nayuki QR-Code-generator v1.8.0 (`python/qrcodegen.py`, SHA-256
    /// b089855c...dcc84): `QrSegment.make_bytes`, `encode_segments(.., LOW, 6, 6, 0,
    /// False)`, as in the Zig test.
    #[test]
    fn complete_matrices_match_independent_version_6_l_byte_mode_mask_zero_vectors() {
        assert_eq!(
            matrix_digest(b"hello"),
            "fedb03e05d2f87205ef2974d1230a91c78c38927bc133b7400270283f9b10a79"
        );
        assert_eq!(
            matrix_digest(
                b"otpauth://totp/Sibuna:18446744073709551615?\
                  secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567\
                  &issuer=Sibuna&algorithm=SHA1&digits=6&period=30"
            ),
            "b291480761779c290ee42743c78c72a0dc3ad5c6827cb2839ea3a543ef18ed2e"
        );
        assert_eq!(
            matrix_digest(&[b'A'; 134]),
            "8aeff1e8995545d4486a8a1674480cc925974edaefe48f5f523224a9a5fbc323"
        );
        let binary: Vec<u8> = (0..134).collect();
        assert_eq!(
            matrix_digest(&binary),
            "c436312d2e84cc9653bfdc30666c519dc67c9a02a7c5259ee2ffc693b8147fe3"
        );
        assert!(encode(&[0; 135]).is_err());
    }

    #[test]
    fn the_svg_draws_one_square_per_dark_module() {
        let qr = encode(b"hello").unwrap();
        let mut text = String::new();
        qr.svg(&mut Html::new(&mut text, 1 << 20)).unwrap();
        let dark = (0..SIZE * SIZE).filter(|index| qr.is_dark(index % SIZE, index / SIZE)).count();
        assert_eq!(text.matches("h1v1h-1z").count(), dark);
        assert!(text.starts_with("<svg class=\"sb-qr\"") && text.ends_with("\"/></svg>"));
    }
}
