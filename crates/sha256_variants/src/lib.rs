//! Experimental SHA-256 implementations, each isolating one optimisation technique
//! so they can be benchmarked head-to-head. All share identical padding and the
//! same round/schedule primitives; only the studied dimension differs.
//!
//! | variant | schedule | compression | extra |
//! |---------|----------|-------------|-------|
//! | `Naive` | tight loop | tight loop, register **copies** | — |
//! | `Unroll8Rotating` | 8-way unrolled | 8-way unrolled, register **copies** (current `sha_256` style) | — |
//! | `Unroll8Renamed` | 8-way unrolled | 8-way unrolled, **renamed** (no copies) | — |
//! | `RenamedKw` | 8-way unrolled, precomputes `W+K` | renamed | K+W folded off critical path |
//! | `RenamedUnchecked` | 8-way unrolled | renamed | `get_unchecked` indexing |
//!
//! Comparisons: Naive↔Unroll8Rotating = manual unrolling; Unroll8Rotating↔
//! Unroll8Renamed = register renaming; Unroll8Renamed↔RenamedKw = K+W
//! pre-combination; Unroll8Renamed↔RenamedUnchecked = bounds-check elision.

use core::convert::TryInto;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

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

#[inline(always)]
fn ssig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[inline(always)]
fn ssig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
#[inline(always)]
fn bsig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[inline(always)]
fn bsig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
#[inline(always)]
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ ((!e) & g)
}
#[inline(always)]
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// One message-schedule word.
macro_rules! sched {
    ($w:expr, $i:expr) => {{
        $w[$i] = $w[$i - 16]
            .wrapping_add(ssig0($w[$i - 15]))
            .wrapping_add($w[$i - 7])
            .wrapping_add(ssig1($w[$i - 2]));
    }};
}

/// One round in the textbook "rotate registers with copies" style.
macro_rules! rot_round {
    ($w:expr, $i:expr, $a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
        let t1 = $h
            .wrapping_add(bsig1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add(K[$i])
            .wrapping_add($w[$i]);
        let t2 = bsig0($a).wrapping_add(maj($a, $b, $c));
        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(t1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = t1.wrapping_add(t2);
    }};
}

/// One round in the "renamed, no-copy" style: only `$d` and `$h` are written; the
/// caller rotates the argument names each round so values flow without copies.
/// `$kw` is the already-combined `W[i] + K[i]`.
macro_rules! rr {
    ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident, $kw:expr) => {{
        $h = $h
            .wrapping_add(bsig1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add($kw);
        $d = $d.wrapping_add($h);
        $h = $h.wrapping_add(bsig0($a)).wrapping_add(maj($a, $b, $c));
    }};
}

/// Eight renamed rounds starting at `$i` (a full name-rotation cycle).
macro_rules! renamed_octet {
    ($w:expr, $kw:ident, $i:expr, $a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
        rr!($a, $b, $c, $d, $e, $f, $g, $h, $kw!($w, $i));
        rr!($h, $a, $b, $c, $d, $e, $f, $g, $kw!($w, $i + 1));
        rr!($g, $h, $a, $b, $c, $d, $e, $f, $kw!($w, $i + 2));
        rr!($f, $g, $h, $a, $b, $c, $d, $e, $kw!($w, $i + 3));
        rr!($e, $f, $g, $h, $a, $b, $c, $d, $kw!($w, $i + 4));
        rr!($d, $e, $f, $g, $h, $a, $b, $c, $kw!($w, $i + 5));
        rr!($c, $d, $e, $f, $g, $h, $a, $b, $kw!($w, $i + 6));
        rr!($b, $c, $d, $e, $f, $g, $h, $a, $kw!($w, $i + 7));
    }};
}

#[inline(always)]
fn load_block(block: &[u8; 64], w: &mut [u32; 64]) {
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
}

#[inline(always)]
fn finish(state: &mut [u32; 8], a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32) {
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

trait Compress {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]);
}

/// Shared padding driver: identical for every variant.
fn hash<C: Compress>(msg: &[u8]) -> [u8; 32] {
    let mut state = IV;
    let full = msg.len() / 64;
    for i in 0..full {
        let block: &[u8; 64] = msg[i * 64..i * 64 + 64].try_into().unwrap();
        C::compress(&mut state, block);
    }
    let rem = &msg[full * 64..];
    let mut buf = [0u8; 128];
    buf[..rem.len()].copy_from_slice(rem);
    buf[rem.len()] = 0x80;
    let bits = (msg.len() as u64) * 8;
    if rem.len() < 56 {
        buf[56..64].copy_from_slice(&bits.to_be_bytes());
        C::compress(&mut state, (&buf[..64]).try_into().unwrap());
    } else {
        buf[120..128].copy_from_slice(&bits.to_be_bytes());
        C::compress(&mut state, (&buf[..64]).try_into().unwrap());
        C::compress(&mut state, (&buf[64..128]).try_into().unwrap());
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

// --- A: naive (tight loops, register copies) -------------------------------
pub struct Naive;
impl Compress for Naive {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        load_block(block, &mut w);
        for i in 16..64 {
            sched!(w, i);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in 0..64 {
            rot_round!(w, i, a, b, c, d, e, f, g, h);
        }
        finish(state, a, b, c, d, e, f, g, h);
    }
}

// --- B: 8-way unrolled, rotating registers (current sha_256 style) ----------
pub struct Unroll8Rotating;
impl Compress for Unroll8Rotating {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        load_block(block, &mut w);
        for i in (16..64).step_by(8) {
            sched!(w, i);
            sched!(w, i + 1);
            sched!(w, i + 2);
            sched!(w, i + 3);
            sched!(w, i + 4);
            sched!(w, i + 5);
            sched!(w, i + 6);
            sched!(w, i + 7);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in (0..64).step_by(8) {
            rot_round!(w, i, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 1, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 2, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 3, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 4, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 5, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 6, a, b, c, d, e, f, g, h);
            rot_round!(w, i + 7, a, b, c, d, e, f, g, h);
        }
        finish(state, a, b, c, d, e, f, g, h);
    }
}

// --- C: 8-way unrolled, renamed (no copies) --------------------------------
macro_rules! kw_inline {
    ($w:expr, $i:expr) => {
        K[$i].wrapping_add($w[$i])
    };
}
pub struct Unroll8Renamed;
impl Compress for Unroll8Renamed {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        load_block(block, &mut w);
        for i in (16..64).step_by(8) {
            sched!(w, i);
            sched!(w, i + 1);
            sched!(w, i + 2);
            sched!(w, i + 3);
            sched!(w, i + 4);
            sched!(w, i + 5);
            sched!(w, i + 6);
            sched!(w, i + 7);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in (0..64).step_by(8) {
            renamed_octet!(w, kw_inline, i, a, b, c, d, e, f, g, h);
        }
        finish(state, a, b, c, d, e, f, g, h);
    }
}

// --- D: renamed + W+K precomputed off the critical path --------------------
macro_rules! kw_array {
    ($wk:expr, $i:expr) => {
        $wk[$i]
    };
}
pub struct RenamedKw;
impl Compress for RenamedKw {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        load_block(block, &mut w);
        for i in (16..64).step_by(8) {
            sched!(w, i);
            sched!(w, i + 1);
            sched!(w, i + 2);
            sched!(w, i + 3);
            sched!(w, i + 4);
            sched!(w, i + 5);
            sched!(w, i + 6);
            sched!(w, i + 7);
        }
        // Fold the round constants in now (cheap, off the compression critical path).
        let mut wk = [0u32; 64];
        for i in 0..64 {
            wk[i] = w[i].wrapping_add(K[i]);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in (0..64).step_by(8) {
            renamed_octet!(wk, kw_array, i, a, b, c, d, e, f, g, h);
        }
        finish(state, a, b, c, d, e, f, g, h);
    }
}

// --- F: renamed + unchecked indexing ---------------------------------------
macro_rules! kw_unchecked {
    ($w:expr, $i:expr) => {
        // Safety: $i is always in 0..64 and $w is [u32; 64].
        unsafe { K.get_unchecked($i).wrapping_add(*$w.get_unchecked($i)) }
    };
}
pub struct RenamedUnchecked;
impl Compress for RenamedUnchecked {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        load_block(block, &mut w);
        // Unchecked schedule.
        for i in (16..64).step_by(8) {
            for j in 0..8 {
                let idx = i + j;
                // Safety: idx in 16..64, all offsets land in 0..64.
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
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in (0..64).step_by(8) {
            renamed_octet!(w, kw_unchecked, i, a, b, c, d, e, f, g, h);
        }
        finish(state, a, b, c, d, e, f, g, h);
    }
}

// --- G: renamed + K+W precompute + unchecked (combined best) ---------------
macro_rules! kw_array_unchecked {
    ($wk:expr, $i:expr) => {
        // Safety: $i in 0..64, $wk is [u32; 64].
        unsafe { *$wk.get_unchecked($i) }
    };
}
pub struct RenamedKwUnchecked;
impl Compress for RenamedKwUnchecked {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        load_block(block, &mut w);
        for i in (16..64).step_by(8) {
            for j in 0..8 {
                let idx = i + j;
                // Safety: idx in 16..64.
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
        let mut wk = [0u32; 64];
        for i in 0..64 {
            // Safety: i in 0..64.
            unsafe {
                *wk.get_unchecked_mut(i) = w.get_unchecked(i).wrapping_add(*K.get_unchecked(i));
            }
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in (0..64).step_by(8) {
            renamed_octet!(wk, kw_array_unchecked, i, a, b, c, d, e, f, g, h);
        }
        finish(state, a, b, c, d, e, f, g, h);
    }
}

macro_rules! variant_api {
    ($name:ident, $imp:ty) => {
        /// Experimental SHA-256 variant; same `new()`/`digest()` API as the crates.
        pub struct $name;
        impl Default for $name {
            fn default() -> Self {
                Self
            }
        }
        impl $name {
            pub fn new() -> Self {
                Self
            }
            pub fn digest(&mut self, msg: &[u8]) -> [u8; 32] {
                hash::<$imp>(msg)
            }
        }
    };
}

variant_api!(Sha256Naive, Naive);
variant_api!(Sha256Unroll8Rotating, Unroll8Rotating);
variant_api!(Sha256Unroll8Renamed, Unroll8Renamed);
variant_api!(Sha256RenamedKw, RenamedKw);
variant_api!(Sha256RenamedUnchecked, RenamedUnchecked);
variant_api!(Sha256RenamedKwUnchecked, RenamedKwUnchecked);

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256 as Theirs};

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

    macro_rules! correctness {
        ($test:ident, $ty:ident) => {
            #[test]
            fn $test() {
                let mut rng = Rng::new(0xabcd_1234);
                let mut ours = $ty::new();
                for len in 0..=300usize {
                    let mut msg = [0u8; 300];
                    for b in msg.iter_mut().take(len) {
                        *b = (rng.next() & 0xff) as u8;
                    }
                    let msg = &msg[..len];
                    assert_eq!(ours.digest(msg), reference(msg), "mismatch at len {}", len);
                }
            }
        };
    }

    correctness!(naive_ok, Sha256Naive);
    correctness!(unroll8_rotating_ok, Sha256Unroll8Rotating);
    correctness!(unroll8_renamed_ok, Sha256Unroll8Renamed);
    correctness!(renamed_kw_ok, Sha256RenamedKw);
    correctness!(renamed_unchecked_ok, Sha256RenamedUnchecked);
    correctness!(renamed_kw_unchecked_ok, Sha256RenamedKwUnchecked);
}
