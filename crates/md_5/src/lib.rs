#![cfg_attr(not(test), no_std)]

//! MD5, structured like the `sha_256` crate: `no_std`, 64-byte blocks, a 64-bit
//! length field, and a `[u32; 16]` scratch array reused across calls. MD5 is the
//! only algorithm in this workspace that is **little-endian**: message words and
//! the length field are loaded/stored little-endian, and there is no message
//! schedule extension (all 64 operations index back into the 16 loaded words).
//! The four 16-operation rounds are each partially unrolled 8 at a time via
//! per-round macros, keeping the same cache-friendly access pattern.
//!
//! MD5 is cryptographically broken (collisions are trivial) and is included for
//! compatibility and benchmarking only — do not use it for security.

use core::convert::TryInto;

// One operation per round; each bakes in its round function and message-word index.
macro_rules! op1 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$w:expr,$i:expr) => {{
        let f = (($b & $c) | ((!$b) & $d))
            .wrapping_add($a)
            .wrapping_add(K[$i])
            .wrapping_add($w[$i & 15]);
        $a = $d;
        $d = $c;
        $c = $b;
        $b = $b.wrapping_add(f.rotate_left(S[$i]));
    }};
}
macro_rules! op2 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$w:expr,$i:expr) => {{
        let f = (($d & $b) | ((!$d) & $c))
            .wrapping_add($a)
            .wrapping_add(K[$i])
            .wrapping_add($w[(5 * $i + 1) & 15]);
        $a = $d;
        $d = $c;
        $c = $b;
        $b = $b.wrapping_add(f.rotate_left(S[$i]));
    }};
}
macro_rules! op3 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$w:expr,$i:expr) => {{
        let f = ($b ^ $c ^ $d)
            .wrapping_add($a)
            .wrapping_add(K[$i])
            .wrapping_add($w[(3 * $i + 5) & 15]);
        $a = $d;
        $d = $c;
        $c = $b;
        $b = $b.wrapping_add(f.rotate_left(S[$i]));
    }};
}
macro_rules! op4 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$w:expr,$i:expr) => {{
        let f = ($c ^ ($b | (!$d)))
            .wrapping_add($a)
            .wrapping_add(K[$i])
            .wrapping_add($w[(7 * $i) & 15]);
        $a = $d;
        $d = $c;
        $c = $b;
        $b = $b.wrapping_add(f.rotate_left(S[$i]));
    }};
}

/// A structure representing the MD5 hash algorithm.
pub struct Md5 {
    w: [u32; 16],
    a0: u32,
    b0: u32,
    c0: u32,
    d0: u32,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// Creates a new instance of the MD5 hash algorithm.
    pub fn new() -> Self {
        Self {
            w: [0; 16],
            a0: 0,
            b0: 0,
            c0: 0,
            d0: 0,
        }
    }

    #[inline(always)]
    fn set_chunk(&mut self, msg: &[u8], index: usize) {
        let start = index * 64;
        let end = start + 64;
        let slice = &msg[start..end];
        for (i, chunk) in slice.chunks_exact(4).enumerate() {
            self.w[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
    }

    #[inline(always)]
    fn set_chunk_last(&mut self, msg: &[u8], index: usize) {
        let msg_len = msg.len();
        let start = index * 64;
        let n_u32s = (msg_len - start) / 4;
        let n_rem_bytes = msg_len % 4;
        let end_u32s = msg_len - n_rem_bytes;

        let slice = &msg[start..end_u32s];
        for (i, chunk) in slice.chunks_exact(4).enumerate() {
            self.w[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        // 0-3 leftover bytes followed by the 0x80 marker, little-endian.
        let mut bytes = [0u8; 4];
        let slice_rem = &msg[end_u32s..];
        bytes[0..n_rem_bytes].copy_from_slice(slice_rem);
        bytes[n_rem_bytes] = 0b10000000;
        self.w[n_u32s] = u32::from_le_bytes(bytes);

        let i = n_u32s + 1;
        self.set_chunk_padding_zeros(i);

        if i <= 14 {
            self.set_chunk_msg_len(msg);
        } else if i == 15 {
            self.w[15] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_msg_len(&mut self, msg: &[u8]) {
        // 64-bit little-endian bit length: low word first (w[14]), high word (w[15]).
        let len = (msg.len() as u64) * 8;
        self.w[14] = len as u32;
        self.w[15] = (len >> 32) as u32;
    }

    #[inline(always)]
    fn set_chunk_padding_zeros(&mut self, start: usize) {
        for i in start..14 {
            self.w[i] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_padding_start_byte(&mut self) {
        // The 0x80 marker is the first byte of the block; little-endian -> low byte of w[0].
        self.w[0] = 0x00000080;
    }

    #[inline(always)]
    fn process_chunk(&mut self) {
        let mut a = self.a0;
        let mut b = self.b0;
        let mut c = self.c0;
        let mut d = self.d0;

        for i in (0..16).step_by(8) {
            op1!(a, b, c, d, self.w, i);
            op1!(a, b, c, d, self.w, i + 1);
            op1!(a, b, c, d, self.w, i + 2);
            op1!(a, b, c, d, self.w, i + 3);
            op1!(a, b, c, d, self.w, i + 4);
            op1!(a, b, c, d, self.w, i + 5);
            op1!(a, b, c, d, self.w, i + 6);
            op1!(a, b, c, d, self.w, i + 7);
        }
        for i in (16..32).step_by(8) {
            op2!(a, b, c, d, self.w, i);
            op2!(a, b, c, d, self.w, i + 1);
            op2!(a, b, c, d, self.w, i + 2);
            op2!(a, b, c, d, self.w, i + 3);
            op2!(a, b, c, d, self.w, i + 4);
            op2!(a, b, c, d, self.w, i + 5);
            op2!(a, b, c, d, self.w, i + 6);
            op2!(a, b, c, d, self.w, i + 7);
        }
        for i in (32..48).step_by(8) {
            op3!(a, b, c, d, self.w, i);
            op3!(a, b, c, d, self.w, i + 1);
            op3!(a, b, c, d, self.w, i + 2);
            op3!(a, b, c, d, self.w, i + 3);
            op3!(a, b, c, d, self.w, i + 4);
            op3!(a, b, c, d, self.w, i + 5);
            op3!(a, b, c, d, self.w, i + 6);
            op3!(a, b, c, d, self.w, i + 7);
        }
        for i in (48..64).step_by(8) {
            op4!(a, b, c, d, self.w, i);
            op4!(a, b, c, d, self.w, i + 1);
            op4!(a, b, c, d, self.w, i + 2);
            op4!(a, b, c, d, self.w, i + 3);
            op4!(a, b, c, d, self.w, i + 4);
            op4!(a, b, c, d, self.w, i + 5);
            op4!(a, b, c, d, self.w, i + 6);
            op4!(a, b, c, d, self.w, i + 7);
        }

        self.a0 = self.a0.wrapping_add(a);
        self.b0 = self.b0.wrapping_add(b);
        self.c0 = self.c0.wrapping_add(c);
        self.d0 = self.d0.wrapping_add(d);
    }

    /// Computes the MD5 digest of the given message.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 16] {
        self.a0 = 0x67452301;
        self.b0 = 0xefcdab89;
        self.c0 = 0x98badcfe;
        self.d0 = 0x10325476;

        let msg_len = msg.len();
        let n_chunks_saturated = msg_len / 64;
        for i in 0..n_chunks_saturated {
            self.set_chunk(msg, i);
            self.process_chunk();
        }

        let msg_rem_len = msg_len % 64;
        if msg_rem_len == 0 {
            self.set_chunk_padding_start_byte();
            self.set_chunk_padding_zeros(1);
            self.set_chunk_msg_len(msg);
        } else {
            self.set_chunk_last(msg, n_chunks_saturated);
        }
        self.process_chunk();
        if msg_rem_len > 55 {
            self.set_chunk_padding_zeros(0);
            self.set_chunk_msg_len(msg);
            self.process_chunk();
        }

        // MD5 emits the four state words little-endian.
        let mut hash = [0; 16];
        hash[0..4].copy_from_slice(&self.a0.to_le_bytes());
        hash[4..8].copy_from_slice(&self.b0.to_le_bytes());
        hash[8..12].copy_from_slice(&self.c0.to_le_bytes());
        hash[12..16].copy_from_slice(&self.d0.to_le_bytes());
        hash
    }
}

/// Per-operation constants: floor(abs(sin(i + 1)) * 2^32).
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Per-operation left-rotation amounts.
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5 as Theirs};

    struct Rng {
        state: u64,
    }

    impl Rng {
        fn new(seed: u64) -> Self {
            Self {
                state: if seed == 0 { 1 } else { seed },
            }
        }
        fn next(&mut self) -> u64 {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            self.state
        }
    }

    fn reference(msg: &[u8]) -> [u8; 16] {
        let mut h = Theirs::new();
        h.update(msg);
        h.finalize().into()
    }

    #[test]
    fn fuzz_vs_reference() {
        let mut rng = Rng::new(0xdead_beef);
        let mut ours = Md5::new();
        for len in 0..=512usize {
            let mut msg = [0u8; 512];
            for b in msg.iter_mut().take(len) {
                *b = (rng.next() & 0xff) as u8;
            }
            let msg = &msg[..len];
            assert_eq!(ours.digest(msg), reference(msg), "mismatch at len {}", len);
        }
        for _ in 0..200 {
            let len = (rng.next() % 4096) as usize;
            let mut msg = [0u8; 4096];
            for b in msg.iter_mut().take(len) {
                *b = (rng.next() & 0xff) as u8;
            }
            let msg = &msg[..len];
            assert_eq!(ours.digest(msg), reference(msg), "mismatch at len {}", len);
        }
    }

    #[test]
    fn known_vectors() {
        let mut h = Md5::new();
        let empty = h.digest(b"");
        assert_eq!(&empty[..4], &[0xd4, 0x1d, 0x8c, 0xd9]); // MD5("")
        assert_eq!(empty, reference(b""));
        assert_eq!(h.digest(b"abc"), reference(b"abc"));
    }
}
