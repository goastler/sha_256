//! SHA-224 accelerated with the Intel SHA extensions (SHA-NI).
//!
//! SHA-224 uses the same compression function as SHA-256 (the SHA-NI instructions
//! are identical), differing only in the IV and the 28-byte truncated output. This
//! speed-tier crate therefore reuses the SHA-NI block compression from `sha_256_ni`
//! and falls back to the portable `sha_224` crate when SHA-NI is unavailable.
//!
//! See `docs/ACCELERATION.md` for the portable-vs-speed strategy.

/// A SHA-224 hasher that uses SHA-NI when available, else the portable fallback.
pub struct Sha224 {
    fallback: sha_224::Sha224,
}

impl Default for Sha224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha224 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            fallback: sha_224::Sha224::new(),
        }
    }

    /// Computes the SHA-224 digest, using the SHA-NI fast path when available.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 28] {
        #[cfg(target_arch = "x86_64")]
        {
            if fast_path_available() {
                // Safety: guarded by runtime feature detection.
                return unsafe { hash_ni(msg) };
            }
        }
        self.fallback.digest(msg)
    }
}

/// Returns true if the SHA-NI hardware fast path will be used on this CPU.
pub fn fast_path_available() -> bool {
    sha_256_ni::fast_path_available()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn hash_ni(msg: &[u8]) -> [u8; 28] {
    // SHA-224 initial hash values.
    let mut state: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];

    let full = msg.len() / 64;
    if full > 0 {
        sha_256_ni::compress_blocks(&mut state, &msg[..full * 64]);
    }

    let rem = &msg[full * 64..];
    let mut buf = [0u8; 128];
    buf[..rem.len()].copy_from_slice(rem);
    buf[rem.len()] = 0x80;
    let bits = (msg.len() as u64) * 8;
    if rem.len() < 56 {
        buf[56..64].copy_from_slice(&bits.to_be_bytes());
        sha_256_ni::compress_blocks(&mut state, &buf[..64]);
    } else {
        buf[120..128].copy_from_slice(&bits.to_be_bytes());
        sha_256_ni::compress_blocks(&mut state, &buf[..128]);
    }

    // SHA-224 emits the first 28 bytes (h0..h6).
    let mut out = [0u8; 28];
    for i in 0..7 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

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
        let mut portable = sha_224::Sha224::new();
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
        if cfg!(target_arch = "x86_64") {
            assert!(fast_path_available(), "expected SHA-NI on this test host");
        }
    }
}
