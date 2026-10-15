//! The block buffer and Merkle-Damgard padding shared by SHA-1, SHA-256 and SHA-512.

/// Collects input into `N`-byte blocks and hands whole blocks to a compression function.
///
/// The buffer never holds a full block: a block is compressed as soon as it is complete, so
/// `len < N` always holds between calls.
#[derive(Clone)]
pub(crate) struct BlockBuffer<const N: usize> {
    block: [u8; N],
    len: usize,
}

impl<const N: usize> BlockBuffer<N> {
    /// An empty buffer.
    pub(crate) const fn new() -> Self {
        Self { block: [0; N], len: 0 }
    }

    /// Feeds `data` through the buffer, calling `compress` with every completed block.
    ///
    /// Whole blocks of `data` are passed to `compress` in one call, without copying, so a
    /// hardware implementation can keep its state in registers across them.
    pub(crate) fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[[u8; N]])) {
        if self.len > 0 {
            let take = (N - self.len).min(data.len());
            self.block[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len < N {
                return;
            }
            compress(core::slice::from_ref(&self.block));
            self.len = 0;
        }
        let (blocks, rest) = data.as_chunks::<N>();
        if !blocks.is_empty() {
            compress(blocks);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// Appends the padding `0x80 0x00 ... length` and compresses the final block or blocks.
    ///
    /// `length` is the big-endian message length in bits, 8 bytes for SHA-1 and SHA-256 and
    /// 16 bytes for SHA-512. It always fits in one block.
    pub(crate) fn finish(&mut self, length: &[u8], mut compress: impl FnMut(&[[u8; N]])) {
        self.block[self.len] = 0x80;
        self.block[self.len + 1..].fill(0);
        if self.len + 1 > N - length.len() {
            compress(core::slice::from_ref(&self.block));
            self.block.fill(0);
        }
        self.block[N - length.len()..].copy_from_slice(length);
        compress(core::slice::from_ref(&self.block));
        self.len = 0;
    }
}
