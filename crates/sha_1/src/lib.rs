#![cfg_attr(not(test), no_std)]

//! SHA-1, structured like the `sha_256` crate: `no_std`, 64-byte blocks, a 64-bit
//! big-endian length field, and a `[u32; 80]` scratch array reused across calls.
//! SHA-1 has 80 rounds split into four 20-round groups, each with its own round
//! function and constant. The message schedule is partially unrolled 8 at a time;
//! the compression groups are unrolled 5 at a time (20 = 4 x 5) via per-group
//! macros, keeping the same cache-friendly array-indexing access pattern.
//!
//! SHA-1 is cryptographically broken (collisions are practical) and is included
//! for compatibility and benchmarking only — do not use it for security.

use core::convert::TryInto;

/// Message-schedule extension: w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1).
macro_rules! schedule {
    ($w:expr, $i:expr) => {{
        $w[$i] = ($w[$i - 3] ^ $w[$i - 8] ^ $w[$i - 14] ^ $w[$i - 16]).rotate_left(1);
    }};
}

// One compression round per group; each bakes in its round function f and constant k.
macro_rules! r1 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$w:expr,$i:expr) => {{
        let f = ($b & $c) | ((!$b) & $d);
        let tmp = $a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add($e)
            .wrapping_add(0x5A827999)
            .wrapping_add($w[$i]);
        $e = $d;
        $d = $c;
        $c = $b.rotate_left(30);
        $b = $a;
        $a = tmp;
    }};
}
macro_rules! r2 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$w:expr,$i:expr) => {{
        let f = $b ^ $c ^ $d;
        let tmp = $a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add($e)
            .wrapping_add(0x6ED9EBA1)
            .wrapping_add($w[$i]);
        $e = $d;
        $d = $c;
        $c = $b.rotate_left(30);
        $b = $a;
        $a = tmp;
    }};
}
macro_rules! r3 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$w:expr,$i:expr) => {{
        let f = ($b & $c) | ($b & $d) | ($c & $d);
        let tmp = $a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add($e)
            .wrapping_add(0x8F1BBCDC)
            .wrapping_add($w[$i]);
        $e = $d;
        $d = $c;
        $c = $b.rotate_left(30);
        $b = $a;
        $a = tmp;
    }};
}
macro_rules! r4 {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$w:expr,$i:expr) => {{
        let f = $b ^ $c ^ $d;
        let tmp = $a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add($e)
            .wrapping_add(0xCA62C1D6)
            .wrapping_add($w[$i]);
        $e = $d;
        $d = $c;
        $c = $b.rotate_left(30);
        $b = $a;
        $a = tmp;
    }};
}

/// A structure representing the SHA-1 hash algorithm.
pub struct Sha1 {
    w: [u32; 80],
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Creates a new instance of the SHA-1 hash algorithm.
    pub fn new() -> Self {
        Self {
            w: [0; 80],
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
        }
    }

    #[inline(always)]
    fn set_chunk(&mut self, msg: &[u8], index: usize) {
        let start = index * 64;
        let end = start + 64;
        let slice = &msg[start..end];
        for (i, chunk) in slice.chunks_exact(4).enumerate() {
            self.w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
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
            self.w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let mut bytes = [0u8; 4];
        let slice_rem = &msg[end_u32s..];
        bytes[0..n_rem_bytes].copy_from_slice(slice_rem);
        bytes[n_rem_bytes] = 0b10000000;
        self.w[n_u32s] = u32::from_be_bytes(bytes);

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
        let len = (msg.len() as u64) * 8;
        self.w[14] = (len >> 32) as u32;
        self.w[15] = len as u32;
    }

    #[inline(always)]
    fn set_chunk_padding_zeros(&mut self, start: usize) {
        for i in start..14 {
            self.w[i] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_padding_start_byte(&mut self) {
        self.w[0] = 0x80000000;
    }

    #[inline(always)]
    fn process_chunk(&mut self) {
        for i in (16..80).step_by(8) {
            schedule!(self.w, i);
            schedule!(self.w, i + 1);
            schedule!(self.w, i + 2);
            schedule!(self.w, i + 3);
            schedule!(self.w, i + 4);
            schedule!(self.w, i + 5);
            schedule!(self.w, i + 6);
            schedule!(self.w, i + 7);
        }

        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;

        for i in (0..20).step_by(5) {
            r1!(a, b, c, d, e, self.w, i);
            r1!(a, b, c, d, e, self.w, i + 1);
            r1!(a, b, c, d, e, self.w, i + 2);
            r1!(a, b, c, d, e, self.w, i + 3);
            r1!(a, b, c, d, e, self.w, i + 4);
        }
        for i in (20..40).step_by(5) {
            r2!(a, b, c, d, e, self.w, i);
            r2!(a, b, c, d, e, self.w, i + 1);
            r2!(a, b, c, d, e, self.w, i + 2);
            r2!(a, b, c, d, e, self.w, i + 3);
            r2!(a, b, c, d, e, self.w, i + 4);
        }
        for i in (40..60).step_by(5) {
            r3!(a, b, c, d, e, self.w, i);
            r3!(a, b, c, d, e, self.w, i + 1);
            r3!(a, b, c, d, e, self.w, i + 2);
            r3!(a, b, c, d, e, self.w, i + 3);
            r3!(a, b, c, d, e, self.w, i + 4);
        }
        for i in (60..80).step_by(5) {
            r4!(a, b, c, d, e, self.w, i);
            r4!(a, b, c, d, e, self.w, i + 1);
            r4!(a, b, c, d, e, self.w, i + 2);
            r4!(a, b, c, d, e, self.w, i + 3);
            r4!(a, b, c, d, e, self.w, i + 4);
        }

        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
    }

    /// Computes the SHA-1 digest of the given message.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 20] {
        self.h0 = 0x67452301;
        self.h1 = 0xEFCDAB89;
        self.h2 = 0x98BADCFE;
        self.h3 = 0x10325476;
        self.h4 = 0xC3D2E1F0;

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

        let mut hash = [0; 20];
        hash[0..4].copy_from_slice(&self.h0.to_be_bytes());
        hash[4..8].copy_from_slice(&self.h1.to_be_bytes());
        hash[8..12].copy_from_slice(&self.h2.to_be_bytes());
        hash[12..16].copy_from_slice(&self.h3.to_be_bytes());
        hash[16..20].copy_from_slice(&self.h4.to_be_bytes());
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest, Sha1 as Theirs};

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

    fn reference(msg: &[u8]) -> [u8; 20] {
        let mut h = Theirs::new();
        h.update(msg);
        h.finalize().into()
    }

    #[test]
    fn fuzz_vs_reference() {
        let mut rng = Rng::new(0xdead_beef);
        let mut ours = Sha1::new();
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
        let mut h = Sha1::new();
        let empty = h.digest(b"");
        assert_eq!(&empty[..4], &[0xda, 0x39, 0xa3, 0xee]); // SHA-1("")
        assert_eq!(empty, reference(b""));
        assert_eq!(h.digest(b"abc"), reference(b"abc"));
    }
}
