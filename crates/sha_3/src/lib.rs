#![cfg_attr(not(test), no_std)]

//! SHA-3 (FIPS 202 fixed-output functions: SHA3-224/256/384/512).
//!
//! Unlike the SHA-2 family this is a *sponge* over the Keccak-f[1600] permutation,
//! not a Merkle–Damgård construction: there is no message-schedule and no length
//! field. The same performance ethos as the `sha_256` crate still applies — the
//! 1600-bit state is a stack-only `[u64; 25]` reused across calls, the inner
//! permutation steps use fixed-size loops the compiler unrolls, and there is zero
//! heap allocation.
//!
//! All four variants share the identical permutation and differ only in their rate
//! (block size) and output length, so they live in one crate.

use core::convert::TryInto;

const ROUNDS: usize = 24;

/// Keccak round constants.
const RC: [u64; ROUNDS] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rho rotation offsets (in the Pi-permuted lane order).
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Pi lane permutation indices.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation, applied in place to the 25-lane state.
#[inline]
fn keccak_f(a: &mut [u64; 25]) {
    for round in 0..ROUNDS {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            let mut y = 0;
            while y < 25 {
                a[y + x] ^= d;
                y += 5;
            }
        }

        // Rho + Pi
        let mut t = a[1];
        for i in 0..24 {
            let j = PI[i];
            let current = a[j];
            a[j] = t.rotate_left(RHO[i]);
            t = current;
        }

        // Chi
        let mut y = 0;
        while y < 25 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = a[y + x];
            }
            for x in 0..5 {
                a[y + x] ^= (!row[(x + 1) % 5]) & row[(x + 2) % 5];
            }
            y += 5;
        }

        // Iota
        a[0] ^= RC[round];
    }
}

/// Absorb `msg` at the given `RATE` (bytes) then squeeze `OUT` bytes. `OUT` is at
/// most `RATE` for every fixed-output SHA-3 variant, so a single squeeze suffices.
#[inline]
fn sponge<const RATE: usize, const OUT: usize>(state: &mut [u64; 25], msg: &[u8]) -> [u8; OUT] {
    let lanes = RATE / 8;

    // Absorb full rate-sized blocks.
    let mut offset = 0;
    while msg.len() - offset >= RATE {
        for i in 0..lanes {
            let chunk = &msg[offset + i * 8..offset + i * 8 + 8];
            state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak_f(state);
        offset += RATE;
    }

    // Final block: remaining bytes + multi-rate padding with SHA-3 domain separation.
    // P = M || 0x06 || 0x00.. with 0x80 OR'd into the last byte of the block.
    let mut block = [0u8; RATE];
    let rem = &msg[offset..];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= 0x06;
    block[RATE - 1] ^= 0x80;
    for i in 0..lanes {
        let chunk = &block[i * 8..i * 8 + 8];
        state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
    keccak_f(state);

    // Squeeze: the leading OUT bytes of the state, lanes little-endian.
    let mut out = [0u8; OUT];
    let mut produced = 0;
    let mut lane = 0;
    while produced < OUT {
        let bytes = state[lane].to_le_bytes();
        let take = if OUT - produced < 8 { OUT - produced } else { 8 };
        out[produced..produced + take].copy_from_slice(&bytes[..take]);
        produced += take;
        lane += 1;
    }
    out
}

macro_rules! sha3_variant {
    ($name:ident, $rate:expr, $out:expr, $doc:literal) => {
        #[doc = $doc]
        pub struct $name {
            state: [u64; 25],
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Creates a new instance of this SHA-3 variant.
            pub fn new() -> Self {
                Self { state: [0; 25] }
            }

            /// Computes the digest of the given message.
            pub fn digest(&mut self, msg: &[u8]) -> [u8; $out] {
                self.state = [0; 25];
                sponge::<$rate, $out>(&mut self.state, msg)
            }
        }
    };
}

// rate = (1600 - 2 * output_bits) / 8 bytes.
sha3_variant!(Sha3_224, 144, 28, "SHA3-224 (rate 144 bytes, 28-byte output).");
sha3_variant!(Sha3_256, 136, 32, "SHA3-256 (rate 136 bytes, 32-byte output).");
sha3_variant!(Sha3_384, 104, 48, "SHA3-384 (rate 104 bytes, 48-byte output).");
sha3_variant!(Sha3_512, 72, 64, "SHA3-512 (rate 72 bytes, 64-byte output).");

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

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

    macro_rules! fuzz_test {
        ($test:ident, $ours:ident, $theirs:ty, $out:expr) => {
            #[test]
            fn $test() {
                fn reference(msg: &[u8]) -> [u8; $out] {
                    let mut h = <$theirs>::new();
                    h.update(msg);
                    h.finalize().into()
                }

                let mut rng = Rng::new(0xdead_beef);
                let mut ours = $ours::new();
                // Cover every length 0..=512 (crosses every rate boundary) + randoms.
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
        };
    }

    fuzz_test!(fuzz_224, Sha3_224, sha3::Sha3_224, 28);
    fuzz_test!(fuzz_256, Sha3_256, sha3::Sha3_256, 32);
    fuzz_test!(fuzz_384, Sha3_384, sha3::Sha3_384, 48);
    fuzz_test!(fuzz_512, Sha3_512, sha3::Sha3_512, 64);

    #[test]
    fn known_vector() {
        // SHA3-256("")
        let mut h = Sha3_256::new();
        assert_eq!(&h.digest(b"")[..4], &[0xa7, 0xff, 0xc6, 0xf8]);
    }
}
