//! Experimental optimised SHA3-256.
//!
//! The shipped `sha_3` crate uses a compact Keccak-f[1600] with runtime `% 5`
//! indexing in theta/chi and array-indexed rho/pi offsets. This variant **fully
//! unrolls** the permutation: every lane index is a compile-time constant, theta's
//! D values and the rho+pi lane chain are written out explicitly (no modulo, no
//! table loads), and chi is unrolled per row. The 24-round loop is kept (only the
//! round constant differs per round). Benchmarked against `sha3` and OpenSSL.

use core::convert::TryInto;

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Fully-unrolled Keccak-f[1600]. All lane indices are compile-time constants.
#[inline]
fn keccak_f(a: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta
        let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);
        a[0] ^= d0; a[5] ^= d0; a[10] ^= d0; a[15] ^= d0; a[20] ^= d0;
        a[1] ^= d1; a[6] ^= d1; a[11] ^= d1; a[16] ^= d1; a[21] ^= d1;
        a[2] ^= d2; a[7] ^= d2; a[12] ^= d2; a[17] ^= d2; a[22] ^= d2;
        a[3] ^= d3; a[8] ^= d3; a[13] ^= d3; a[18] ^= d3; a[23] ^= d3;
        a[4] ^= d4; a[9] ^= d4; a[14] ^= d4; a[19] ^= d4; a[24] ^= d4;

        // Rho + Pi: the fixed lane chain, unrolled with constant offsets.
        let mut t = a[1];
        let mut cur;
        cur = a[10]; a[10] = t.rotate_left(1); t = cur;
        cur = a[7]; a[7] = t.rotate_left(3); t = cur;
        cur = a[11]; a[11] = t.rotate_left(6); t = cur;
        cur = a[17]; a[17] = t.rotate_left(10); t = cur;
        cur = a[18]; a[18] = t.rotate_left(15); t = cur;
        cur = a[3]; a[3] = t.rotate_left(21); t = cur;
        cur = a[5]; a[5] = t.rotate_left(28); t = cur;
        cur = a[16]; a[16] = t.rotate_left(36); t = cur;
        cur = a[8]; a[8] = t.rotate_left(45); t = cur;
        cur = a[21]; a[21] = t.rotate_left(55); t = cur;
        cur = a[24]; a[24] = t.rotate_left(2); t = cur;
        cur = a[4]; a[4] = t.rotate_left(14); t = cur;
        cur = a[15]; a[15] = t.rotate_left(27); t = cur;
        cur = a[23]; a[23] = t.rotate_left(41); t = cur;
        cur = a[19]; a[19] = t.rotate_left(56); t = cur;
        cur = a[13]; a[13] = t.rotate_left(8); t = cur;
        cur = a[12]; a[12] = t.rotate_left(25); t = cur;
        cur = a[2]; a[2] = t.rotate_left(43); t = cur;
        cur = a[20]; a[20] = t.rotate_left(62); t = cur;
        cur = a[14]; a[14] = t.rotate_left(18); t = cur;
        cur = a[22]; a[22] = t.rotate_left(39); t = cur;
        cur = a[9]; a[9] = t.rotate_left(61); t = cur;
        cur = a[6]; a[6] = t.rotate_left(20); t = cur;
        a[1] = t.rotate_left(44);

        // Chi, unrolled per row.
        let (b0, b1, b2, b3, b4) = (a[0], a[1], a[2], a[3], a[4]);
        a[0] = b0 ^ ((!b1) & b2);
        a[1] = b1 ^ ((!b2) & b3);
        a[2] = b2 ^ ((!b3) & b4);
        a[3] = b3 ^ ((!b4) & b0);
        a[4] = b4 ^ ((!b0) & b1);
        let (b0, b1, b2, b3, b4) = (a[5], a[6], a[7], a[8], a[9]);
        a[5] = b0 ^ ((!b1) & b2);
        a[6] = b1 ^ ((!b2) & b3);
        a[7] = b2 ^ ((!b3) & b4);
        a[8] = b3 ^ ((!b4) & b0);
        a[9] = b4 ^ ((!b0) & b1);
        let (b0, b1, b2, b3, b4) = (a[10], a[11], a[12], a[13], a[14]);
        a[10] = b0 ^ ((!b1) & b2);
        a[11] = b1 ^ ((!b2) & b3);
        a[12] = b2 ^ ((!b3) & b4);
        a[13] = b3 ^ ((!b4) & b0);
        a[14] = b4 ^ ((!b0) & b1);
        let (b0, b1, b2, b3, b4) = (a[15], a[16], a[17], a[18], a[19]);
        a[15] = b0 ^ ((!b1) & b2);
        a[16] = b1 ^ ((!b2) & b3);
        a[17] = b2 ^ ((!b3) & b4);
        a[18] = b3 ^ ((!b4) & b0);
        a[19] = b4 ^ ((!b0) & b1);
        let (b0, b1, b2, b3, b4) = (a[20], a[21], a[22], a[23], a[24]);
        a[20] = b0 ^ ((!b1) & b2);
        a[21] = b1 ^ ((!b2) & b3);
        a[22] = b2 ^ ((!b3) & b4);
        a[23] = b3 ^ ((!b4) & b0);
        a[24] = b4 ^ ((!b0) & b1);

        // Iota
        a[0] ^= RC[round];
    }
}

const RATE: usize = 136; // SHA3-256
const OUT: usize = 32;

/// Optimised SHA3-256.
pub struct Sha3_256Opt {
    state: [u64; 25],
}

impl Default for Sha3_256Opt {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256Opt {
    pub fn new() -> Self {
        Self { state: [0; 25] }
    }

    pub fn digest(&mut self, msg: &[u8]) -> [u8; OUT] {
        let state = &mut self.state;
        *state = [0; 25];
        let lanes = RATE / 8;

        let mut offset = 0;
        while msg.len() - offset >= RATE {
            for i in 0..lanes {
                let chunk = &msg[offset + i * 8..offset + i * 8 + 8];
                state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
            }
            keccak_f(state);
            offset += RATE;
        }

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
}

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

    fn reference(msg: &[u8]) -> [u8; 32] {
        let mut h = sha3::Sha3_256::new();
        h.update(msg);
        h.finalize().into()
    }

    #[test]
    fn opt_matches_reference() {
        let mut rng = Rng::new(0xc0ffee);
        let mut ours = Sha3_256Opt::new();
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
