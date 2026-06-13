//! Experimental optimised SHA-512: the shipped `sha_512` structure plus the two
//! scalar techniques that helped SHA-256 in `sha256_variants` — K+W
//! pre-combination (fold the round constant into the schedule, off the
//! compression critical path) and `get_unchecked` indexing (bounds-check elision).
//! Register "renaming" is also used, though it was neutral for SHA-256 (LLVM
//! already removes the copies). Benchmarked against RustCrypto / ring / openssl,
//! all of which are scalar for SHA-512 on CPUs without a SHA-512 instruction.

use core::convert::TryInto;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

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

#[inline(always)]
fn ssig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
#[inline(always)]
fn ssig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
#[inline(always)]
fn bsig0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
#[inline(always)]
fn bsig1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
#[inline(always)]
fn ch(e: u64, f: u64, g: u64) -> u64 {
    (e & f) ^ ((!e) & g)
}
#[inline(always)]
fn maj(a: u64, b: u64, c: u64) -> u64 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// Renamed, no-copy round; `$wk` is the pre-combined `W[i] + K[i]`.
macro_rules! rr {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident, $wk:expr) => {{
        $h = $h
            .wrapping_add(bsig1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add($wk);
        $d = $d.wrapping_add($h);
        $h = $h.wrapping_add(bsig0($a)).wrapping_add(maj($a, $b, $c));
    }};
}

macro_rules! octet {
    ($wk:expr, $i:expr, $a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
        // Safety: indices $i..$i+7 are always < 80.
        unsafe {
            rr!($a, $b, $c, $d, $e, $f, $g, $h, *$wk.get_unchecked($i));
            rr!($h, $a, $b, $c, $d, $e, $f, $g, *$wk.get_unchecked($i + 1));
            rr!($g, $h, $a, $b, $c, $d, $e, $f, *$wk.get_unchecked($i + 2));
            rr!($f, $g, $h, $a, $b, $c, $d, $e, *$wk.get_unchecked($i + 3));
            rr!($e, $f, $g, $h, $a, $b, $c, $d, *$wk.get_unchecked($i + 4));
            rr!($d, $e, $f, $g, $h, $a, $b, $c, *$wk.get_unchecked($i + 5));
            rr!($c, $d, $e, $f, $g, $h, $a, $b, *$wk.get_unchecked($i + 6));
            rr!($b, $c, $d, $e, $f, $g, $h, $a, *$wk.get_unchecked($i + 7));
        }
    }};
}

#[inline(always)]
fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    for i in (16..80).step_by(8) {
        for j in 0..8 {
            let idx = i + j;
            // Safety: idx in 16..80, all offsets land in 0..80.
            unsafe {
                let v = w
                    .get_unchecked(idx - 16)
                    .wrapping_add(ssig0(*w.get_unchecked(idx - 15)))
                    .wrapping_add(*w.get_unchecked(idx - 7))
                    .wrapping_add(ssig1(*w.get_unchecked(idx - 2)));
                *w.get_unchecked_mut(idx) = v;
            }
        }
    }
    // K+W pre-combination, off the compression critical path.
    let mut wk = [0u64; 80];
    for i in 0..80 {
        unsafe {
            *wk.get_unchecked_mut(i) = w.get_unchecked(i).wrapping_add(*K.get_unchecked(i));
        }
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    for i in (0..80).step_by(8) {
        octet!(wk, i, a, b, c, d, e, f, g, h);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Optimised SHA-512.
pub struct Sha512Opt;

impl Default for Sha512Opt {
    fn default() -> Self {
        Self
    }
}

impl Sha512Opt {
    pub fn new() -> Self {
        Self
    }

    pub fn digest(&mut self, msg: &[u8]) -> [u8; 64] {
        let mut state = IV;
        let full = msg.len() / 128;
        for i in 0..full {
            let block: &[u8; 128] = msg[i * 128..i * 128 + 128].try_into().unwrap();
            compress(&mut state, block);
        }
        let rem = &msg[full * 128..];
        let mut buf = [0u8; 256];
        buf[..rem.len()].copy_from_slice(rem);
        buf[rem.len()] = 0x80;
        let bits = (msg.len() as u128) * 8;
        if rem.len() < 112 {
            buf[112..128].copy_from_slice(&bits.to_be_bytes());
            compress(&mut state, (&buf[..128]).try_into().unwrap());
        } else {
            buf[240..256].copy_from_slice(&bits.to_be_bytes());
            compress(&mut state, (&buf[..128]).try_into().unwrap());
            compress(&mut state, (&buf[128..256]).try_into().unwrap());
        }
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha512 as Theirs};

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

    fn reference(msg: &[u8]) -> [u8; 64] {
        let mut h = Theirs::new();
        h.update(msg);
        h.finalize().into()
    }

    #[test]
    fn opt_matches_reference() {
        let mut rng = Rng::new(0x5eed);
        let mut ours = Sha512Opt::new();
        for len in 0..=600usize {
            let mut msg = [0u8; 600];
            for b in msg.iter_mut().take(len) {
                *b = (rng.next() & 0xff) as u8;
            }
            let msg = &msg[..len];
            assert_eq!(ours.digest(msg), reference(msg), "mismatch at len {}", len);
        }
    }
}
