//! CRC-32 as gzip (RFC 1952) and zlib use it: the reflected polynomial `0xEDB88320`, an
//! initial value and final XOR of all ones.
//!
//! The update works on sixteen bytes at a time through sixteen lookup tables ("slicing by
//! sixteen", 16 KiB of tables). The gzip decoder checksums every output byte, so this is
//! a visible part of decompression time: one table lookup per byte runs at about 400 MiB/s,
//! slicing by eight at about 2 GiB/s, and slicing by sixteen faster still.

/// The reflected generator polynomial of CRC-32.
const POLYNOMIAL: u32 = 0xEDB8_8320;

/// How many bytes one step of the update consumes.
const SLICES: usize = 16;

/// `TABLES[0]` is the classic byte table; `TABLES[k][b]` is the CRC of byte `b` followed by
/// `k` zero bytes, so sixteen table lookups advance the CRC by sixteen bytes.
static TABLES: [[u32; 256]; SLICES] = build_tables();

const fn build_tables() -> [[u32; 256]; SLICES] {
    let mut tables = [[0u32; 256]; SLICES];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { POLYNOMIAL ^ (crc >> 1) } else { crc >> 1 };
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }
    let mut byte = 0;
    while byte < 256 {
        let mut slice = 1;
        while slice < SLICES {
            let previous = tables[slice - 1][byte];
            tables[slice][byte] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            slice += 1;
        }
        byte += 1;
    }
    tables
}

/// A running CRC-32 over a byte stream.
///
/// Feed the bytes with [`Crc32::update`] in as many pieces as convenient; the result does not
/// depend on how the stream was split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crc32 {
    /// The register before the final XOR.
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Returns the CRC of the empty stream, ready for [`Crc32::update`].
    pub const fn new() -> Self {
        Self { state: !0 }
    }

    /// Extends the CRC with `data`, which it reads but does not keep.
    pub fn update(&mut self, data: &[u8]) {
        let t = &TABLES;
        let mut crc = self.state;
        let (blocks, rest) = data.as_chunks::<SLICES>();
        for block in blocks {
            // Byte `i` of the block goes through table `15 - i`; the CRC is XORed into the
            // first four bytes. Indexes are bytes, so every lookup is in bounds.
            let mut next = 0;
            for (i, &byte) in block.iter().enumerate() {
                let byte = if i < 4 { byte ^ (crc >> (8 * i)) as u8 } else { byte };
                next ^= t[SLICES - 1 - i][usize::from(byte)];
            }
            crc = next;
        }
        for &byte in rest {
            crc = (crc >> 8) ^ t[0][((crc ^ u32::from(byte)) & 0xff) as usize];
        }
        self.state = crc;
    }

    /// Returns the CRC of all bytes fed so far. The running CRC is unchanged, so more bytes
    /// may follow.
    pub const fn value(&self) -> u32 {
        !self.state
    }
}

/// Returns the CRC-32 of `data` in one call.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference implementation: one table lookup per byte.
    fn bytewise(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in data {
            crc = (crc >> 8) ^ TABLES[0][((crc ^ u32::from(byte)) & 0xff) as usize];
        }
        !crc
    }

    #[test]
    fn known_values() {
        // The check value of CRC-32/ISO-HDLC from the CRC catalogue.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        // The footer of Zig's "gzip non compressed block" test: CRC of "Hello world\n".
        assert_eq!(crc32(b"Hello world\n"), 0xB739_E0D5);
    }

    #[test]
    fn slicing_matches_bytewise_for_every_split() {
        let data: Vec<u8> =
            (0..300u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for len in 0..data.len() {
            assert_eq!(crc32(&data[..len]), bytewise(&data[..len]), "length {len}");
        }
        for split in 0..data.len() {
            let mut crc = Crc32::new();
            crc.update(&data[..split]);
            crc.update(&data[split..]);
            assert_eq!(crc.value(), bytewise(&data), "split {split}");
        }
    }
}
