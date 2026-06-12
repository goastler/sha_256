//! SHA-256 accelerated with the Intel SHA extensions (SHA-NI).
//!
//! This is a **speed-tier** crate: it is `std` (it uses runtime CPU detection via
//! `is_x86_feature_detected!`) and dispatches to a SHA-NI hardware path when the
//! CPU supports it, falling back to the portable `sha_256` crate otherwise. The
//! public API matches the rest of the workspace: `Sha256::new().digest(msg)`.
//!
//! See `docs/ACCELERATION.md` for the portable-vs-speed strategy.

/// A SHA-256 hasher that uses SHA-NI when available, else the portable fallback.
pub struct Sha256 {
    fallback: sha_256::Sha256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            fallback: sha_256::Sha256::new(),
        }
    }

    /// Computes the SHA-256 digest, using the SHA-NI fast path when available.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 32] {
        #[cfg(target_arch = "x86_64")]
        {
            if fast_path_available() {
                // Safety: guarded by runtime feature detection above.
                return unsafe { ni::hash(msg) };
            }
        }
        self.fallback.digest(msg)
    }
}

/// Returns true if the SHA-NI hardware fast path will be used on this CPU.
pub fn fast_path_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse4.1")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// The raw SHA-NI block compression, re-exported for sibling speed crates
/// (e.g. `sha_224_ni`) that share the SHA-256 compression with a different IV.
/// Not part of the stable public API.
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub use ni::compress_blocks;

#[cfg(target_arch = "x86_64")]
mod ni {
    use core::arch::x86_64::*;

    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Hash a full message with SHA-NI: process whole blocks, then the padded tail.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn hash(msg: &[u8]) -> [u8; 32] {
        let mut state = IV;

        let full = msg.len() / 64;
        if full > 0 {
            compress_blocks(&mut state, &msg[..full * 64]);
        }

        // Build the padded final block(s): 0x80 marker + 64-bit big-endian bit length.
        let rem = &msg[full * 64..];
        let mut buf = [0u8; 128];
        buf[..rem.len()].copy_from_slice(rem);
        buf[rem.len()] = 0x80;
        let bits = (msg.len() as u64) * 8;
        if rem.len() < 56 {
            buf[56..64].copy_from_slice(&bits.to_be_bytes());
            compress_blocks(&mut state, &buf[..64]);
        } else {
            buf[120..128].copy_from_slice(&bits.to_be_bytes());
            compress_blocks(&mut state, &buf[..128]);
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }

    /// SHA-NI compression over `data.len() / 64` blocks. Canonical Gulley/noloader
    /// sequence ported to `core::arch`.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress_blocks(state: &mut [u32; 8], data: &[u8]) {
        let mask = _mm_set_epi64x(0x0c0d0e0f08090a0bu64 as i64, 0x0405060700010203u64 as i64);

        let mut tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let mut state1 = _mm_loadu_si128(state[4..].as_ptr() as *const __m128i);

        tmp = _mm_shuffle_epi32::<0xB1>(tmp); // CDAB
        state1 = _mm_shuffle_epi32::<0x1B>(state1); // EFGH
        let mut state0 = _mm_alignr_epi8::<8>(tmp, state1); // ABEF
        state1 = _mm_blend_epi16::<0xF0>(state1, tmp); // CDGH

        let mut ptr = data.as_ptr();
        let mut len = data.len();
        while len >= 64 {
            let abef_save = state0;
            let cdgh_save = state1;

            // Rounds 0-3
            let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(ptr as *const __m128i), mask);
            let mut msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0xE9B5DBA5B5C0FBCFu64 as i64, 0x71374491428A2F98u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 4-7
            let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(16) as *const __m128i), mask);
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0xAB1C5ED5923F82A4u64 as i64, 0x59F111F13956C25Bu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 8-11
            let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(32) as *const __m128i), mask);
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0x550C7DC3243185BEu64 as i64, 0x12835B01D807AA98u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 12-15
            let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(48) as *const __m128i), mask);
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0xC19BF1749BDC06A7u64 as i64, 0x80DEB1FE72BE5D74u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg3, msg2);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 16-19
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0x240CA1CC0FC19DC6u64 as i64, 0xEFBE4786E49B69C1u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg0, msg3);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 20-23
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0x76F988DA5CB0A9DCu64 as i64, 0x4A7484AA2DE92C6Fu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg1, msg0);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 24-27
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0xBF597FC7B00327C8u64 as i64, 0xA831C66D983E5152u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg2, msg1);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 28-31
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0x1429296706CA6351u64 as i64, 0xD5A79147C6E00BF3u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg3, msg2);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 32-35
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0x53380D134D2C6DFCu64 as i64, 0x2E1B213827B70A85u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg0, msg3);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 36-39
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0x92722C8581C2C92Eu64 as i64, 0x766A0ABB650A7354u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg1, msg0);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 40-43
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0xC76C51A3C24B8B70u64 as i64, 0xA81A664BA2BFE8A1u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg2, msg1);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 44-47
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0x106AA070F40E3585u64 as i64, 0xD6990624D192E819u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg3, msg2);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 48-51
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0x34B0BCB52748774Cu64 as i64, 0x1E376C0819A4C116u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg0, msg3);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 52-55
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0x682E6FF35B9CCA4Fu64 as i64, 0x4ED8AA4A391C0CB3u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg1, msg0);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 56-59
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0x8CC7020884C87814u64 as i64, 0x78A5636F748F82EEu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8::<4>(msg2, msg1);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 60-63
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0xC67178F2BEF9A3F7u64 as i64, 0xA4506CEB90BEFFFAu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            state0 = _mm_add_epi32(state0, abef_save);
            state1 = _mm_add_epi32(state1, cdgh_save);

            ptr = ptr.add(64);
            len -= 64;
        }

        tmp = _mm_shuffle_epi32::<0x1B>(state0); // FEBA
        state1 = _mm_shuffle_epi32::<0xB1>(state1); // DCHG
        state0 = _mm_blend_epi16::<0xF0>(tmp, state1); // DCBA
        state1 = _mm_alignr_epi8::<8>(state1, tmp); // ABEF -> HGFE

        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state0);
        _mm_storeu_si128(state[4..].as_mut_ptr() as *mut __m128i, state1);
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
    fn fuzz_vs_reference() {
        let mut rng = Rng::new(0xdead_beef);
        let mut ours = Sha256::new();
        let mut portable = sha_256::Sha256::new();
        for len in 0..=512usize {
            let mut msg = [0u8; 512];
            for b in msg.iter_mut().take(len) {
                *b = (rng.next() & 0xff) as u8;
            }
            let msg = &msg[..len];
            let got = ours.digest(msg);
            assert_eq!(got, reference(msg), "vs sha2 mismatch at len {}", len);
            assert_eq!(got, portable.digest(msg), "vs portable mismatch at len {}", len);
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
    fn fast_path_engaged_on_this_cpu() {
        // This crate is being developed/tested on a SHA-NI capable CPU; make sure
        // the fast path is actually what we exercised above (not just the fallback).
        if cfg!(target_arch = "x86_64") {
            assert!(
                fast_path_available(),
                "expected SHA-NI on this test host; the fast path was not exercised"
            );
        }
    }
}
