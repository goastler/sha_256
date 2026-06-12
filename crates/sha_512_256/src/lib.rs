#![cfg_attr(not(test), no_std)]

//! SHA-512/256: the SHA-512 core with the SHA-512/256 IV and the output truncated
//! to the first 32 bytes (4 of the 8 state words). Structured identically to
//! `sha_256`, but on 64-bit words: 128-byte blocks, 80 rounds, an 80-entry message
//! schedule, a 128-bit length field, and a `[u64; 80]` scratch array reused across
//! calls. The schedule and compression loops are partially unrolled 8 at a time
//! via macros, keeping the same cache-friendly array-indexing access pattern.

use core::convert::TryInto;

macro_rules! schedule {
    ($w:expr, $i:expr) => {{
        let w15 = $w[$i - 15];
        let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
        let w2 = $w[$i - 2];
        let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
        $w[$i] = $w[$i - 16]
            .wrapping_add(s0)
            .wrapping_add($w[$i - 7])
            .wrapping_add(s1);
    }};
}

macro_rules! round {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident,$w:expr,$i:expr) => {{
        let s1 = $e.rotate_right(14) ^ $e.rotate_right(18) ^ $e.rotate_right(41);
        let ch = ($e & $f) ^ ((!$e) & $g);
        let temp1 = $h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[$i])
            .wrapping_add($w[$i]);
        let s0 = $a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39);
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

/// A structure representing the SHA-512/256 hash algorithm.
pub struct Sha512_256 {
    w: [u64; 80],
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
}

impl Default for Sha512_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512_256 {
    /// Creates a new instance of the SHA-512/256 hash algorithm.
    pub fn new() -> Self {
        Self {
            w: [0; 80],
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
        let start = index * 128;
        let end = start + 128;
        let slice = &msg[start..end];
        for (i, chunk) in slice.chunks_exact(8).enumerate() {
            self.w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
    }

    #[inline(always)]
    fn set_chunk_last(&mut self, msg: &[u8], index: usize) {
        let msg_len = msg.len();
        let start = index * 128;
        let n_u64s = (msg_len - start) / 8;
        let n_rem_bytes = msg_len % 8;
        let end_u64s = msg_len - n_rem_bytes;

        let slice = &msg[start..end_u64s];
        for (i, chunk) in slice.chunks_exact(8).enumerate() {
            self.w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }

        let mut bytes = [0u8; 8];
        let slice_rem = &msg[end_u64s..];
        bytes[0..n_rem_bytes].copy_from_slice(slice_rem);
        bytes[n_rem_bytes] = 0b10000000;
        self.w[n_u64s] = u64::from_be_bytes(bytes);

        let i = n_u64s + 1;
        self.set_chunk_padding_zeros(i);

        if i <= 14 {
            self.set_chunk_msg_len(msg);
        } else if i == 15 {
            self.w[15] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_msg_len(&mut self, msg: &[u8]) {
        let len = (msg.len() as u128) * 8;
        self.w[14] = (len >> 64) as u64;
        self.w[15] = len as u64;
    }

    #[inline(always)]
    fn set_chunk_padding_zeros(&mut self, start: usize) {
        for i in start..14 {
            self.w[i] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_padding_start_byte(&mut self) {
        self.w[0] = 0x8000000000000000;
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
        let mut f = self.h5;
        let mut g = self.h6;
        let mut h = self.h7;

        for i in (0..80).step_by(8) {
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

    /// Computes the SHA-512/256 digest of the given message.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 32] {
        self.h0 = 0x22312194fc2bf72c;
        self.h1 = 0x9f555fa3c84c64c2;
        self.h2 = 0x2393b86b6f53b151;
        self.h3 = 0x963877195940eabd;
        self.h4 = 0x96283ee2a88effe3;
        self.h5 = 0xbe5e1e2553863992;
        self.h6 = 0x2b0199fc2c85b8aa;
        self.h7 = 0x0eb72ddc81c52ca2;

        let msg_len = msg.len();
        let n_chunks_saturated = msg_len / 128;
        for i in 0..n_chunks_saturated {
            self.set_chunk(msg, i);
            self.process_chunk();
        }

        let msg_rem_len = msg_len % 128;
        if msg_rem_len == 0 {
            self.set_chunk_padding_start_byte();
            self.set_chunk_padding_zeros(1);
            self.set_chunk_msg_len(msg);
        } else {
            self.set_chunk_last(msg, n_chunks_saturated);
        }
        self.process_chunk();
        if msg_rem_len > 111 {
            self.set_chunk_padding_zeros(0);
            self.set_chunk_msg_len(msg);
            self.process_chunk();
        }

        // SHA-512/256 emits the first 32 bytes (h0..h3).
        let mut hash = [0; 32];
        hash[0..8].copy_from_slice(&self.h0.to_be_bytes());
        hash[8..16].copy_from_slice(&self.h1.to_be_bytes());
        hash[16..24].copy_from_slice(&self.h2.to_be_bytes());
        hash[24..32].copy_from_slice(&self.h3.to_be_bytes());
        hash
    }
}

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha512_256 as Theirs};

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

    fn reference(msg: &[u8]) -> [u8; 32] {
        let mut h = Theirs::new();
        h.update(msg);
        h.finalize().into()
    }

    #[test]
    fn fuzz_vs_reference() {
        let mut rng = Rng::new(0xdead_beef);
        let mut ours = Sha512_256::new();
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
        let mut h = Sha512_256::new();
        let empty = h.digest(b"");
        assert_eq!(&empty[..4], &[0xc6, 0x72, 0xb8, 0xd1]); // SHA-512/256("")
        assert_eq!(empty, reference(b""));
        assert_eq!(h.digest(b"abc"), reference(b"abc"));
    }
}
