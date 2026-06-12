//! SHA-1 accelerated with the Intel SHA extensions (SHA-NI).
//!
//! Speed-tier crate: `std` with runtime CPU detection, dispatching to a SHA-NI
//! hardware path and falling back to the portable `sha_1` crate otherwise. The
//! public API matches the rest of the workspace: `Sha1::new().digest(msg)`.
//!
//! SHA-1 is cryptographically broken; included for compatibility/benchmarking only.
//! See `docs/ACCELERATION.md` for the portable-vs-speed strategy.

/// A SHA-1 hasher that uses SHA-NI when available, else the portable fallback.
pub struct Sha1 {
    fallback: sha_1::Sha1,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            fallback: sha_1::Sha1::new(),
        }
    }

    /// Computes the SHA-1 digest, using the SHA-NI fast path when available.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 20] {
        #[cfg(target_arch = "x86_64")]
        {
            if fast_path_available() {
                // Safety: guarded by runtime feature detection.
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

#[cfg(target_arch = "x86_64")]
mod ni {
    use core::arch::x86_64::*;

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn hash(msg: &[u8]) -> [u8; 20] {
        let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

        let full = msg.len() / 64;
        if full > 0 {
            compress_blocks(&mut state, &msg[..full * 64]);
        }

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

        let mut out = [0u8; 20];
        for i in 0..5 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }

    /// SHA-NI compression over `data.len() / 64` blocks. Canonical Gulley/noloader
    /// sequence ported to `core::arch`.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn compress_blocks(state: &mut [u32; 5], data: &[u8]) {
        let mask = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);

        let mut abcd = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);
        abcd = _mm_shuffle_epi32::<0x1B>(abcd);

        let mut ptr = data.as_ptr();
        let mut len = data.len();
        while len >= 64 {
            let abcd_save = abcd;
            let e0_save = e0;
            let mut e1;

            // Rounds 0-3
            let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(ptr as *const __m128i), mask);
            e0 = _mm_add_epi32(e0, msg0);
            e1 = abcd;
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);

            // Rounds 4-7
            let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(16) as *const __m128i), mask);
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);

            // Rounds 8-11
            let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(32) as *const __m128i), mask);
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 12-15
            let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(48) as *const __m128i), mask);
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 16-19
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 20-23
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 24-27
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 28-31
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 32-35
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 36-39
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 40-43
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 44-47
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 48-51
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 52-55
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 56-59
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 60-63
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 64-67
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 68-71
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 72-75
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);

            // Rounds 76-79
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);

            // Combine state
            e0 = _mm_sha1nexte_epu32(e0, e0_save);
            abcd = _mm_add_epi32(abcd, abcd_save);

            ptr = ptr.add(64);
            len -= 64;
        }

        abcd = _mm_shuffle_epi32::<0x1B>(abcd);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, abcd);
        state[4] = _mm_extract_epi32::<3>(e0) as u32;
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
        let mut portable = sha_1::Sha1::new();
        for len in 0..=512usize {
            let mut msg = [0u8; 512];
            for b in msg.iter_mut().take(len) {
                *b = (rng.next() & 0xff) as u8;
            }
            let msg = &msg[..len];
            let got = ours.digest(msg);
            assert_eq!(got, reference(msg), "vs sha1 mismatch at len {}", len);
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
        if cfg!(target_arch = "x86_64") {
            assert!(fast_path_available(), "expected SHA-NI on this test host");
        }
    }
}
