#![cfg_attr(not(test), no_std)]

//! SHA-224: the SHA-256 core with a different IV and the output truncated to the
//! first 28 bytes (7 of the 8 state words). Same performant structure as the
//! `sha_256` crate: `no_std`, 64-byte blocks, 64 rounds, a 64-entry message
//! schedule, a 64-bit length field, and a `[u32; 64]` scratch array reused across
//! calls. The schedule and compression loops are partially unrolled 8 at a time
//! via macros, keeping the same cache-friendly array-indexing access pattern.

use core::convert::TryInto;

macro_rules! schedule {
    ($w:expr, $i:expr) => {{
        let w15 = $w[$i - 15];
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let w2 = $w[$i - 2];
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        $w[$i] = $w[$i - 16]
            .wrapping_add(s0)
            .wrapping_add($w[$i - 7])
            .wrapping_add(s1);
    }};
}

macro_rules! round {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident,$w:expr,$i:expr) => {{
        let s1 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
        let ch = ($e & $f) ^ ((!$e) & $g);
        let temp1 = $h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[$i])
            .wrapping_add($w[$i]);
        let s0 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
        let maj = ($a & $b) ^ ($a & $c) ^ ($b & $c);
        let temp2 = s0.wrapping_add(maj);

        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(temp1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = temp1.wrapping_add(temp2);
    }};
}

/// A structure representing the SHA-224 hash algorithm.
pub struct Sha224 {
    w: [u32; 64],
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
}

impl Default for Sha224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha224 {
    /// Creates a new instance of the SHA-224 hash algorithm.
    pub fn new() -> Self {
        Self {
            w: [0; 64],
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            h5: 0,
            h6: 0,
            h7: 0,
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
        for i in (16..64).step_by(8) {
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
        let mut f = self.h5;
        let mut g = self.h6;
        let mut h = self.h7;

        for i in (0..64).step_by(8) {
            round!(a, b, c, d, e, f, g, h, self.w, i);
            round!(a, b, c, d, e, f, g, h, self.w, i + 1);
            round!(a, b, c, d, e, f, g, h, self.w, i + 2);
            round!(a, b, c, d, e, f, g, h, self.w, i + 3);
            round!(a, b, c, d, e, f, g, h, self.w, i + 4);
            round!(a, b, c, d, e, f, g, h, self.w, i + 5);
            round!(a, b, c, d, e, f, g, h, self.w, i + 6);
            round!(a, b, c, d, e, f, g, h, self.w, i + 7);
        }

        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
        self.h5 = self.h5.wrapping_add(f);
        self.h6 = self.h6.wrapping_add(g);
        self.h7 = self.h7.wrapping_add(h);
    }

    /// Computes the SHA-224 digest of the given message.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 28] {
        self.h0 = 0xc1059ed8;
        self.h1 = 0x367cd507;
        self.h2 = 0x3070dd17;
        self.h3 = 0xf70e5939;
        self.h4 = 0xffc00b31;
        self.h5 = 0x68581511;
        self.h6 = 0x64f98fa7;
        self.h7 = 0xbefa4fa4;

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

        // SHA-224 emits the first 28 bytes (h0..h6).
        let mut hash = [0; 28];
        hash[0..4].copy_from_slice(&self.h0.to_be_bytes());
        hash[4..8].copy_from_slice(&self.h1.to_be_bytes());
        hash[8..12].copy_from_slice(&self.h2.to_be_bytes());
        hash[12..16].copy_from_slice(&self.h3.to_be_bytes());
        hash[16..20].copy_from_slice(&self.h4.to_be_bytes());
        hash[20..24].copy_from_slice(&self.h5.to_be_bytes());
        hash[24..28].copy_from_slice(&self.h6.to_be_bytes());
        hash
    }
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha224 as Theirs};

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

    fn reference(msg: &[u8]) -> [u8; 28] {
        let mut h = Theirs::new();
        h.update(msg);
        h.finalize().into()
    }

    #[test]
    fn fuzz_vs_reference() {
        let mut rng = Rng::new(0xdead_beef);
        let mut ours = Sha224::new();
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
        let mut h = Sha224::new();
        let empty = h.digest(b"");
        assert_eq!(&empty[..4], &[0xd1, 0x4a, 0x02, 0x8c]); // SHA-224("")
        assert_eq!(empty, reference(b""));
        assert_eq!(h.digest(b"abc"), reference(b"abc"));
    }
}
