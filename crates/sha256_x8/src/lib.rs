//! 8-way AVX2 batched SHA-256: hashes **8 independent, equal-length messages in
//! parallel**, one per 32-bit SIMD lane. This is the one technique that can beat a
//! single-stream SHA-NI library on aggregate throughput, because SHA-NI advances
//! only one stream at a time while this advances eight.
//!
//! API: [`hash8`] takes 8 byte slices (all the same length) and returns 8 digests.
//! When AVX2 is unavailable it falls back to hashing the 8 messages with the
//! portable `sha_256` crate.
//!
//! All eight messages share the SHA-256 IV, so every lane starts identically; only
//! the message bytes differ. Equal length is required so the 8 lanes step through
//! the same block/padding layout in lockstep (the common batched use case: Merkle
//! trees, proof-of-work, bulk verification).

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

/// Hash 8 equal-length messages, returning 8 SHA-256 digests.
///
/// # Panics
/// Panics if the 8 inputs are not all the same length.
pub fn hash8(inputs: &[&[u8]; 8]) -> [[u8; 32]; 8] {
    let len = inputs[0].len();
    assert!(
        inputs.iter().all(|m| m.len() == len),
        "hash8 requires all 8 inputs to be the same length"
    );

    #[cfg(target_arch = "x86_64")]
    {
        if avx2_available() {
            // Safety: guarded by runtime feature detection.
            return unsafe { avx2::hash8(inputs, len) };
        }
    }

    // Portable fallback: hash each message independently.
    let mut out = [[0u8; 32]; 8];
    let mut h = sha_256::Sha256::new();
    for k in 0..8 {
        out[k] = h.digest(inputs[k]);
    }
    out
}

/// Returns true if the AVX2 fast path will be used on this CPU.
pub fn avx2_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::{IV, K};
    use core::arch::x86_64::*;

    /// Rotate-right each 32-bit lane by a compile-time constant.
    macro_rules! rotr {
        ($x:expr, $n:expr) => {
            _mm256_or_si256(
                _mm256_srli_epi32::<{ $n }>($x),
                _mm256_slli_epi32::<{ 32 - $n }>($x),
            )
        };
    }

    #[inline(always)]
    unsafe fn ssig0(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(rotr!(x, 7), rotr!(x, 18)),
            _mm256_srli_epi32::<3>(x),
        )
    }
    #[inline(always)]
    unsafe fn ssig1(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(rotr!(x, 17), rotr!(x, 19)),
            _mm256_srli_epi32::<10>(x),
        )
    }
    #[inline(always)]
    unsafe fn bsig0(x: __m256i) -> __m256i {
        _mm256_xor_si256(_mm256_xor_si256(rotr!(x, 2), rotr!(x, 13)), rotr!(x, 22))
    }
    #[inline(always)]
    unsafe fn bsig1(x: __m256i) -> __m256i {
        _mm256_xor_si256(_mm256_xor_si256(rotr!(x, 6), rotr!(x, 11)), rotr!(x, 25))
    }
    #[inline(always)]
    unsafe fn ch(e: __m256i, f: __m256i, g: __m256i) -> __m256i {
        // (e & f) ^ (!e & g)
        _mm256_xor_si256(_mm256_and_si256(e, f), _mm256_andnot_si256(e, g))
    }
    #[inline(always)]
    unsafe fn maj(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
        // (a & b) ^ (a & c) ^ (b & c)
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_and_si256(a, b), _mm256_and_si256(a, c)),
            _mm256_and_si256(b, c),
        )
    }

    /// Load message word `j` from all 8 lanes (big-endian) at byte offset `off`.
    #[inline(always)]
    unsafe fn load_word(inputs: &[&[u8]; 8], off: usize) -> __m256i {
        let mut vals = [0u32; 8];
        for k in 0..8 {
            let b = &inputs[k][off..off + 4];
            vals[k] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        _mm256_loadu_si256(vals.as_ptr() as *const __m256i)
    }

    /// Load message word `j` from 8 per-lane 64-byte buffers (big-endian).
    #[inline(always)]
    unsafe fn load_word_buf(blocks: &[[u8; 64]; 8], j: usize) -> __m256i {
        let mut vals = [0u32; 8];
        for k in 0..8 {
            let o = j * 4;
            vals[k] = u32::from_be_bytes([
                blocks[k][o],
                blocks[k][o + 1],
                blocks[k][o + 2],
                blocks[k][o + 3],
            ]);
        }
        _mm256_loadu_si256(vals.as_ptr() as *const __m256i)
    }

    #[target_feature(enable = "avx2")]
    unsafe fn compress(state: &mut [__m256i; 8], w16: &[__m256i; 16]) {
        let mut w = [_mm256_setzero_si256(); 64];
        w[..16].copy_from_slice(w16);
        for i in 16..64 {
            w[i] = _mm256_add_epi32(
                _mm256_add_epi32(w[i - 16], ssig0(w[i - 15])),
                _mm256_add_epi32(w[i - 7], ssig1(w[i - 2])),
            );
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let kv = _mm256_set1_epi32(K[i] as i32);
            let t1 = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(_mm256_add_epi32(h, bsig1(e)), ch(e, f, g)),
                    kv,
                ),
                w[i],
            );
            let t2 = _mm256_add_epi32(bsig0(a), maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = _mm256_add_epi32(d, t1);
            d = c;
            c = b;
            b = a;
            a = _mm256_add_epi32(t1, t2);
        }

        state[0] = _mm256_add_epi32(state[0], a);
        state[1] = _mm256_add_epi32(state[1], b);
        state[2] = _mm256_add_epi32(state[2], c);
        state[3] = _mm256_add_epi32(state[3], d);
        state[4] = _mm256_add_epi32(state[4], e);
        state[5] = _mm256_add_epi32(state[5], f);
        state[6] = _mm256_add_epi32(state[6], g);
        state[7] = _mm256_add_epi32(state[7], h);
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn hash8(inputs: &[&[u8]; 8], len: usize) -> [[u8; 32]; 8] {
        let mut state = [
            _mm256_set1_epi32(IV[0] as i32),
            _mm256_set1_epi32(IV[1] as i32),
            _mm256_set1_epi32(IV[2] as i32),
            _mm256_set1_epi32(IV[3] as i32),
            _mm256_set1_epi32(IV[4] as i32),
            _mm256_set1_epi32(IV[5] as i32),
            _mm256_set1_epi32(IV[6] as i32),
            _mm256_set1_epi32(IV[7] as i32),
        ];

        let full = len / 64;
        for blk in 0..full {
            let base = blk * 64;
            let mut w16 = [_mm256_setzero_si256(); 16];
            for j in 0..16 {
                w16[j] = load_word(inputs, base + j * 4);
            }
            compress(&mut state, &w16);
        }

        // Final padded block(s); identical layout across lanes (equal length).
        let rem = len % 64;
        let bits = (len as u64) * 8;
        let mut pad = [[0u8; 64]; 8];
        let mut pad2 = [[0u8; 64]; 8];
        let two = rem >= 56;
        for k in 0..8 {
            let tail = &inputs[k][full * 64..];
            pad[k][..rem].copy_from_slice(tail);
            pad[k][rem] = 0x80;
            if two {
                pad2[k][56..64].copy_from_slice(&bits.to_be_bytes());
            } else {
                pad[k][56..64].copy_from_slice(&bits.to_be_bytes());
            }
        }
        let mut w16 = [_mm256_setzero_si256(); 16];
        for j in 0..16 {
            w16[j] = load_word_buf(&pad, j);
        }
        compress(&mut state, &w16);
        if two {
            for j in 0..16 {
                w16[j] = load_word_buf(&pad2, j);
            }
            compress(&mut state, &w16);
        }

        // Transpose state back to per-lane digests.
        let mut words = [[0u32; 8]; 8]; // words[state_word][lane]
        for s in 0..8 {
            _mm256_storeu_si256(words[s].as_mut_ptr() as *mut __m256i, state[s]);
        }
        let mut out = [[0u8; 32]; 8];
        for lane in 0..8 {
            for s in 0..8 {
                out[lane][s * 4..s * 4 + 4].copy_from_slice(&words[s][lane].to_be_bytes());
            }
        }
        out
    }
}

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

    #[test]
    fn hash8_matches_reference() {
        let mut rng = Rng::new(0x8888_1234);
        // Cover every length 0..=300 (all padding paths, 1- and 2-block tails).
        for len in 0..=300usize {
            let mut bufs = [[0u8; 300]; 8];
            for k in 0..8 {
                for b in bufs[k].iter_mut().take(len) {
                    *b = (rng.next() & 0xff) as u8;
                }
            }
            let slices: [&[u8]; 8] = [
                &bufs[0][..len], &bufs[1][..len], &bufs[2][..len], &bufs[3][..len],
                &bufs[4][..len], &bufs[5][..len], &bufs[6][..len], &bufs[7][..len],
            ];
            let got = hash8(&slices);
            for k in 0..8 {
                assert_eq!(got[k], reference(slices[k]), "lane {} mismatch at len {}", k, len);
            }
        }
    }
}
