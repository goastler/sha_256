#![cfg_attr(not(test), no_std)]

use core::convert::TryInto;
use core::iter::Iterator;

/// A structure representing the SHA-256 hash algorithm.
pub struct Sha256 {
    w: [u32; 64], // words for the message schedule
    // the 8 hash values
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Creates a new instance of the SHA-256 hash algorithm.
    ///
    /// # Returns
    /// A new `Sha256` instance with initialized state.
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

    /// Sets a chunk of the message for SHA-256 processing.
    ///
    /// # Arguments
    /// * `msg` - A byte slice representing the message to be hashed.
    /// * `index` - The index of the chunk to be set.
    #[inline(always)]
    fn set_chunk(&mut self, msg: &[u8], index: usize) {
        unsafe {
            // message entirely saturates this chunk, so straight-up copy the bytes into u32's
            let start = index * 64;
            let end = start + 64;
            let slice = &msg[start..end];
            for (i, chunk) in slice.chunks_exact(4).enumerate() {
                self.w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
        }
    }

    #[inline(always)]
    fn set_chunk_last(&mut self, msg: &[u8], index: usize) {
        // copy the remaining msg into the w array
        let msg_len = msg.len();
        let start = index * 64;
        let n_u32s = (msg_len - start) / 4; // how many 4 byte blocks are in the remaining message
        let n_rem_bytes = msg_len % 4; // how many leftover bytes are in the remaining message after the 4 byte blocks
        let end_u32s = msg_len - n_rem_bytes;
        // for every 4 byte chunk in the remaining message
        let slice = &msg[start..end_u32s];
        for (i, chunk) in slice.chunks_exact(4).enumerate() {
            // convert the 4 byte chunk into a u32 and store it in the w array
            self.w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        
        // there will be 0-3 bytes left over which didn't fit into the 4 byte chunks
        // copy these into a 4 byte chunk
        let mut bytes = [0u8; 4];
        let slice_rem = &msg[end_u32s..];
        bytes[0..n_rem_bytes].copy_from_slice(slice_rem);
        // after the msg ends, we pad with a 0b10000000 byte
        bytes[n_rem_bytes] = 0b10000000;
        // convert the bytes into a u32
        self.w[n_u32s] = u32::from_be_bytes(bytes);

        // any u32s after the message but before the last 2 u32s are 0
        let i = n_u32s + 1;
        self.set_chunk_padding_zeros(msg, i);

        // if the message length is <=55 bytes and >=1 byte, the padding will fit into the last chunk
        // a message of <=55 bytes will have space for the length field in this chunk
        // 55 bytes of message + 1 byte of padding = 56 bytes = 14 u32s
        // length field goes in w[14] and w[15]
        if i <= 14 {
            // space for length field
            // remaining message fits into the last chunk with padding included.
            self.set_chunk_msg_len(msg);
        } else if i == 15 {
            // else no space for length field, so will be in next chunk
            // set where length field would have been to 0's
            self.w[15] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_msg_len(&mut self, msg: &[u8]) {
        // the last 2 u32s are the length of the message in bits
        let msg_len = msg.len();
        let len = (msg_len * 8) as u64;
        let len_upper_bytes = ((len >> 32) as u32).to_be_bytes();
        let len_lower_bytes = ((len & 0xFFFFFFFF) as u32).to_be_bytes();
        self.w[14] = u32::from_be_bytes(len_upper_bytes);
        self.w[15] = u32::from_be_bytes(len_lower_bytes);
    }

    #[inline(always)]
    fn set_chunk_padding_zeros(&mut self, msg: &[u8], start: usize) {
        // the padding is all zeros except for the last 2 u32s which are the length of the message in bits
        for i in start..14 {
            self.w[i] = 0;
        }
    }

    #[inline(always)]
    fn set_chunk_padding_start_byte(&mut self) {
        // set a u32 to [0b10000000, 0, 0, 0]. The first by is 0b10000000, which is the flag to indicate the start of padding
        self.w[0] = 2147483648; // [0b10000000, 0, 0, 0] converted to u32
    }

    /// Processes a single chunk of the message using the SHA-256 algorithm.
    #[inline(always)]
    fn process_chunk(&mut self) {
        unsafe {
            // Extend w to 64 words
            // partially unrolled loop, 8 iterations at a time
            // why 8? gets a reasonable amount of variable reuse through the indexing of the w array, but doesn't unroll the loop too a point where the code size is too large for the gains
            for i in (16..64).step_by(8) {
                // could reuse repeats of variables, but we don't because benchmarks show it's slower. I _think_ it's something to do with cache hits for array elements being faster than reusing variables

                // First iteration: i
                let w15_0 = self.w[i - 15];
                let s0_0 = w15_0.rotate_right(7) ^ w15_0.rotate_right(18) ^ (w15_0 >> 3);
                let w2_0 = self.w[i - 2];
                let s1_0 = w2_0.rotate_right(17) ^ w2_0.rotate_right(19) ^ (w2_0 >> 10);
                self.w[i] = self.w[i - 16]
                    .wrapping_add(s0_0)
                    .wrapping_add(self.w[i - 7])
                    .wrapping_add(s1_0);

                // Second iteration: i + 1
                let w15_1 = self.w[i - 14];
                let s0_1 = w15_1.rotate_right(7) ^ w15_1.rotate_right(18) ^ (w15_1 >> 3);
                let w2_1 = self.w[i - 1];
                let s1_1 = w2_1.rotate_right(17) ^ w2_1.rotate_right(19) ^ (w2_1 >> 10);
                self.w[i + 1] = self.w[i - 15]
                    .wrapping_add(s0_1)
                    .wrapping_add(self.w[i - 6])
                    .wrapping_add(s1_1);

                // Third iteration: i + 2
                let w15_2 = self.w[i - 13];
                let s0_2 = w15_2.rotate_right(7) ^ w15_2.rotate_right(18) ^ (w15_2 >> 3);
                let w2_2 = self.w[i];
                let s1_2 = w2_2.rotate_right(17) ^ w2_2.rotate_right(19) ^ (w2_2 >> 10);
                self.w[i + 2] = self.w[i - 14]
                    .wrapping_add(s0_2)
                    .wrapping_add(self.w[i - 5])
                    .wrapping_add(s1_2);

                // Fourth iteration: i + 3
                let w15_3 = self.w[i - 12];
                let s0_3 = w15_3.rotate_right(7) ^ w15_3.rotate_right(18) ^ (w15_3 >> 3);
                let w2_3 = self.w[i + 1];
                let s1_3 = w2_3.rotate_right(17) ^ w2_3.rotate_right(19) ^ (w2_3 >> 10);
                self.w[i + 3] = self.w[i - 13]
                    .wrapping_add(s0_3)
                    .wrapping_add(self.w[i - 4])
                    .wrapping_add(s1_3);

                // Fifth iteration: i + 4
                let w15_4 = self.w[i - 11];
                let s0_4 = w15_4.rotate_right(7) ^ w15_4.rotate_right(18) ^ (w15_4 >> 3);
                let w2_4 = self.w[i + 2];
                let s1_4 = w2_4.rotate_right(17) ^ w2_4.rotate_right(19) ^ (w2_4 >> 10);
                self.w[i + 4] = self.w[i - 12]
                    .wrapping_add(s0_4)
                    .wrapping_add(self.w[i - 3])
                    .wrapping_add(s1_4);

                // Sixth iteration: i + 5
                let w15_5 = self.w[i - 10];
                let s0_5 = w15_5.rotate_right(7) ^ w15_5.rotate_right(18) ^ (w15_5 >> 3);
                let w2_5 = self.w[i + 3];
                let s1_5 = w2_5.rotate_right(17) ^ w2_5.rotate_right(19) ^ (w2_5 >> 10);
                self.w[i + 5] = self.w[i - 11]
                    .wrapping_add(s0_5)
                    .wrapping_add(self.w[i - 2])
                    .wrapping_add(s1_5);

                // Seventh iteration: i + 6
                let w15_6 = self.w[i - 9];
                let s0_6 = w15_6.rotate_right(7) ^ w15_6.rotate_right(18) ^ (w15_6 >> 3);
                let w2_6 = self.w[i + 4];
                let s1_6 = w2_6.rotate_right(17) ^ w2_6.rotate_right(19) ^ (w2_6 >> 10);
                self.w[i + 6] = self.w[i - 10]
                    .wrapping_add(s0_6)
                    .wrapping_add(self.w[i - 1])
                    .wrapping_add(s1_6);

                // Eighth iteration: i + 7
                let w15_7 = self.w[i - 8];
                let s0_7 = w15_7.rotate_right(7) ^ w15_7.rotate_right(18) ^ (w15_7 >> 3);
                let w2_7 = self.w[i + 5];
                let s1_7 = w2_7.rotate_right(17) ^ w2_7.rotate_right(19) ^ (w2_7 >> 10);
                self.w[i + 7] = self.w[i - 9]
                    .wrapping_add(s0_7)
                    .wrapping_add(self.w[i])
                    .wrapping_add(s1_7);
            }

            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;
            let mut f = self.h5;
            let mut g = self.h6;
            let mut h = self.h7;

            // partially unrolled loop, 8 iterations at a time
            for i in (0..64).step_by(8) {
                // First iteration: i
                let s1_0 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_0 = (e & f) ^ ((!e) & g);
                let temp1_0 = h
                    .wrapping_add(s1_0)
                    .wrapping_add(ch_0)
                    .wrapping_add(K[i])
                    .wrapping_add(self.w[i]);
                let s0_0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_0 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_0 = s0_0.wrapping_add(maj_0);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_0);
                d = c;
                c = b;
                b = a;
                a = temp1_0.wrapping_add(temp2_0);

                // Second iteration: i + 1
                let s1_1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_1 = (e & f) ^ ((!e) & g);
                let temp1_1 = h
                    .wrapping_add(s1_1)
                    .wrapping_add(ch_1)
                    .wrapping_add(K[i + 1])
                    .wrapping_add(self.w[i + 1]);
                let s0_1 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_1 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_1 = s0_1.wrapping_add(maj_1);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_1);
                d = c;
                c = b;
                b = a;
                a = temp1_1.wrapping_add(temp2_1);

                // Third iteration: i + 2
                let s1_2 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_2 = (e & f) ^ ((!e) & g);
                let temp1_2 = h
                    .wrapping_add(s1_2)
                    .wrapping_add(ch_2)
                    .wrapping_add(K[i + 2])
                    .wrapping_add(self.w[i + 2]);
                let s0_2 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_2 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_2 = s0_2.wrapping_add(maj_2);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_2);
                d = c;
                c = b;
                b = a;
                a = temp1_2.wrapping_add(temp2_2);

                // Fourth iteration: i + 3
                let s1_3 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_3 = (e & f) ^ ((!e) & g);
                let temp1_3 = h
                    .wrapping_add(s1_3)
                    .wrapping_add(ch_3)
                    .wrapping_add(K[i + 3])
                    .wrapping_add(self.w[i + 3]);
                let s0_3 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_3 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_3 = s0_3.wrapping_add(maj_3);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_3);
                d = c;
                c = b;
                b = a;
                a = temp1_3.wrapping_add(temp2_3);

                // Fifth iteration: i + 4
                let s1_4 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_4 = (e & f) ^ ((!e) & g);
                let temp1_4 = h
                    .wrapping_add(s1_4)
                    .wrapping_add(ch_4)
                    .wrapping_add(K[i + 4])
                    .wrapping_add(self.w[i + 4]);
                let s0_4 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_4 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_4 = s0_4.wrapping_add(maj_4);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_4);
                d = c;
                c = b;
                b = a;
                a = temp1_4.wrapping_add(temp2_4);

                // Sixth iteration: i + 5
                let s1_5 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_5 = (e & f) ^ ((!e) & g);
                let temp1_5 = h
                    .wrapping_add(s1_5)
                    .wrapping_add(ch_5)
                    .wrapping_add(K[i + 5])
                    .wrapping_add(self.w[i + 5]);
                let s0_5 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_5 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_5 = s0_5.wrapping_add(maj_5);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_5);
                d = c;
                c = b;
                b = a;
                a = temp1_5.wrapping_add(temp2_5);

                // Seventh iteration: i + 6
                let s1_6 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_6 = (e & f) ^ ((!e) & g);
                let temp1_6 = h
                    .wrapping_add(s1_6)
                    .wrapping_add(ch_6)
                    .wrapping_add(K[i + 6])
                    .wrapping_add(self.w[i + 6]);
                let s0_6 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_6 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_6 = s0_6.wrapping_add(maj_6);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_6);
                d = c;
                c = b;
                b = a;
                a = temp1_6.wrapping_add(temp2_6);

                // Eighth iteration: i + 7
                let s1_7 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_7 = (e & f) ^ ((!e) & g);
                let temp1_7 = h
                    .wrapping_add(s1_7)
                    .wrapping_add(ch_7)
                    .wrapping_add(K[i + 7])
                    .wrapping_add(self.w[i + 7]);
                let s0_7 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_7 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_7 = s0_7.wrapping_add(maj_7);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_7);
                d = c;
                c = b;
                b = a;
                a = temp1_7.wrapping_add(temp2_7);
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
    }

    /// Computes the SHA-256 digest of the given message.
    ///
    /// # Arguments
    /// * `msg` - A byte slice representing the message to be hashed.
    ///
    /// # Returns
    /// A 32-byte array representing the SHA-256 hash of the message.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 32] {
        self.h0 = 0x6a09e667;
        self.h1 = 0xbb67ae85;
        self.h2 = 0x3c6ef372;
        self.h3 = 0xa54ff53a;
        self.h4 = 0x510e527f;
        self.h5 = 0x9b05688c;
        self.h6 = 0x1f83d9ab;
        self.h7 = 0x5be0cd19;

        let msg_len = msg.len();
        let n_chunks_saturated = msg_len / 64; // how many full chunks the message fits into
        // for each chunk (64 bytes) of the message
        for i in 0..n_chunks_saturated {
            self.set_chunk(msg, i);
            self.process_chunk();
        }

        let msg_rem_len = msg_len % 64; // how many bytes from the message do not fit into a full chunk
        // the remaining message length is 0-63 bytes
        // the padding is 9 bytes (1 for the 0b10000000 byte, 8 for the message length in bits)
        // therefore:
            // a message of 1-55 bytes will fit into the last chunk WITH padding
            // a message of 56-63 bytes will require the 0b10000000 byte to be in the last chunk as the message, but the message length need an extra chunk
            // a message of 0 bytes will also require the extra chunk, but the 0b10000000 byte will be in the same chunk as the message length


        if msg_rem_len == 0 {
            self.set_chunk_padding_start_byte();
            self.set_chunk_padding_zeros(msg, 1);
            self.set_chunk_msg_len(msg);
        } else {
            // copy the remaining message into the w array
            self.set_chunk_last(msg, n_chunks_saturated);
        }
        self.process_chunk();
        if msg_rem_len > 55 {
            // an extra chunk is required for the padding
            // padding is all zeros with the message length in bits at the end
            self.set_chunk_padding_zeros(msg, 0);
            self.set_chunk_msg_len(msg);
            self.process_chunk();
        }

        // Create the output hash
        let mut hash = [0; 32];
        unsafe {
            hash[0..4].copy_from_slice(&self.h0.to_be_bytes());
            hash[4..8].copy_from_slice(&self.h1.to_be_bytes());
            hash[8..12].copy_from_slice(&self.h2.to_be_bytes());
            hash[12..16].copy_from_slice(&self.h3.to_be_bytes());
            hash[16..20].copy_from_slice(&self.h4.to_be_bytes());
            hash[20..24].copy_from_slice(&self.h5.to_be_bytes());
            hash[24..28].copy_from_slice(&self.h6.to_be_bytes());
            hash[28..32].copy_from_slice(&self.h7.to_be_bytes());
        }

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
    use sha2::{digest::generic_array::GenericArray, Digest, Sha256 as Theirs};

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

    #[test]
    fn test_against_sha2_lib() {
        // generate random messages

        let mut rng = Rng::new(0);

        let limit = 100_000;
        let mut count: usize = 0;
        let mut ours = Sha256::new();
        loop {
            let mut theirs = sha2::Sha256::new();
            let mut message_bytes = Vec::<u8>::new();
            let i = rng.next() % 1024;
            for _ in 0..=i {
                message_bytes.push((rng.next() % 255) as u8); // 'a'
            }
            let hash = ours.digest(&message_bytes);
            theirs.update(&message_bytes);
            let hash2 = theirs.finalize();
            println!("our hash: {:?}", hash);
            println!("their hash: {:?}", hash2);
            assert_eq!(hash, hash2.as_slice(), "hashes[{}] with {}x'a'", i, i+1);
            
            count += 1;
            if count == limit {
                break;
            }
        }
        println!("total test cases: {}", count);
    }

    #[test]
    fn hash_hello() {
		let mut sha256 = Sha256::new();
		let message_bytes = &[104, 101, 108, 108, 111];
		let hash = sha256.digest(message_bytes);
		assert_eq!(hash, [
            44, 242, 77, 186,  95, 176, 163,  14,
            38, 232, 59,  42, 197, 185, 226, 158,
            27,  22, 30,  92,  31, 167,  66,  94,
           115,   4, 51,  98, 147, 139, 152,  36
         ]);
    }

    #[test]
    fn hash_empty() {
		let mut sha256 = Sha256::new();
		let message_bytes = &[];
		let hash = sha256.digest(message_bytes);
		assert_eq!(hash, [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85
         ]);
    }

    // the first 1024 hashes of strings of length 0-1024 bytes, where each byte is 'a'. E.g:
    // ''
    // 'a'
    // 'aa'
    // 'aaa'
    // ...
    const HASHES: [[u8; 32]; 1024] = [[202, 151, 129, 18, 202, 27, 189, 202, 250, 194, 49, 179, 154, 35, 220, 77, 167, 134, 239, 248, 20, 124, 78, 114, 185, 128, 119, 133, 175, 238, 72, 187],
    [150, 27, 109, 211, 237, 227, 203, 142, 203, 170, 203, 214, 141, 224, 64, 205, 120, 235, 46, 213, 136, 145, 48, 204, 235, 76, 73, 38, 142, 164, 213, 6],
    [152, 52, 135, 109, 207, 176, 92, 177, 103, 165, 194, 73, 83, 235, 165, 140, 74, 200, 155, 26, 223, 87, 242, 143, 47, 157, 9, 175, 16, 126, 232, 240],
    [97, 190, 85, 168, 226, 246, 180, 225, 114, 51, 139, 221, 241, 132, 214, 219, 238, 41, 201, 136, 83, 224, 160, 72, 94, 206, 231, 242, 123, 154, 240, 180],
    [237, 150, 142, 132, 13, 16, 210, 211, 19, 168, 112, 188, 19, 26, 78, 44, 49, 29, 122, 208, 155, 223, 50, 179, 65, 129, 71, 34, 31, 81, 166, 226],
    [237, 2, 69, 123, 92, 65, 217, 100, 219, 210, 242, 166, 9, 214, 63, 225, 187, 117, 40, 219, 229, 94, 26, 191, 91, 82, 194, 73, 205, 115, 87, 151],
    [228, 98, 64, 113, 75, 93, 179, 162, 62, 238, 96, 71, 154, 98, 62, 251, 164, 214, 51, 210, 127, 228, 240, 60, 144, 75, 158, 33, 154, 127, 190, 96],
    [31, 60, 228, 4, 21, 162, 8, 31, 163, 238, 231, 95, 195, 159, 255, 142, 86, 194, 34, 112, 209, 169, 120, 167, 36, 155, 89, 45, 206, 189, 32, 180],
    [242, 172, 169, 59, 128, 202, 230, 129, 34, 31, 4, 69, 250, 78, 44, 174, 138, 31, 159, 143, 161, 225, 116, 29, 150, 57, 202, 173, 34, 47, 83, 125],
    [191, 44, 181, 138, 104, 246, 132, 217, 90, 59, 120, 239, 143, 102, 28, 154, 78, 91, 9, 232, 44, 200, 249, 204, 136, 204, 233, 5, 40, 202, 235, 39],
    [40, 203, 1, 125, 252, 153, 7, 58, 161, 180, 124, 27, 48, 244, 19, 227, 206, 119, 76, 73, 145, 235, 65, 88, 222, 80, 249, 219, 179, 109, 128, 67],
    [242, 74, 188, 52, 177, 63, 173, 231, 110, 128, 87, 153, 247, 17, 135, 218, 108, 217, 11, 156, 172, 55, 58, 230, 94, 213, 127, 20, 59, 214, 100, 229],
    [166, 137, 215, 134, 232, 19, 64, 228, 85, 17, 222, 198, 199, 171, 45, 151, 132, 52, 229, 219, 18, 51, 98, 69, 15, 225, 12, 250, 199, 13, 25, 208],
    [130, 202, 183, 223, 10, 191, 185, 217, 93, 202, 78, 89, 55, 206, 41, 104, 199, 152, 199, 38, 254, 164, 140, 1, 107, 249, 118, 50, 33, 239, 218, 19],
    [239, 45, 240, 181, 57, 198, 194, 61, 224, 244, 203, 228, 38, 72, 195, 1, 174, 14, 34, 232, 135, 52, 10, 69, 153, 251, 78, 244, 226, 103, 142, 72],
    [12, 11, 234, 206, 248, 135, 123, 191, 36, 22, 235, 0, 242, 181, 220, 150, 53, 78, 38, 221, 29, 245, 81, 115, 32, 69, 155, 18, 54, 134, 15, 140],
    [184, 96, 102, 110, 226, 150, 109, 216, 249, 3, 190, 68, 238, 96, 92, 110, 19, 102, 249, 38, 217, 241, 122, 143, 73, 147, 125, 17, 98, 78, 185, 157],
    [201, 38, 222, 250, 170, 61, 19, 237, 162, 252, 99, 165, 83, 187, 127, 183, 50, 107, 236, 230, 231, 203, 103, 202, 82, 150, 228, 114, 125, 137, 186, 180],
    [160, 180, 170, 171, 138, 150, 110, 33, 147, 186, 23, 45, 104, 22, 44, 70, 86, 134, 1, 151, 242, 86, 181, 244, 95, 2, 3, 57, 127, 243, 249, 156],
    [66, 73, 45, 160, 98, 52, 173, 10, 199, 111, 93, 93, 235, 219, 109, 26, 224, 39, 207, 251, 231, 70, 161, 193, 59, 137, 187, 139, 192, 19, 145, 55],
    [125, 248, 226, 153, 200, 52, 222, 25, 142, 38, 76, 62, 55, 75, 197, 142, 205, 147, 130, 37, 42, 112, 92, 24, 59, 235, 2, 242, 117, 87, 30, 59],
    [236, 124, 73, 77, 246, 210, 167, 234, 54, 102, 141, 101, 110, 107, 137, 121, 227, 54, 65, 191, 234, 55, 140, 21, 3, 138, 243, 150, 77, 176, 87, 163],
    [137, 125, 62, 149, 182, 95, 38, 103, 96, 129, 248, 185, 243, 169, 139, 110, 228, 66, 69, 102, 48, 62, 141, 78, 124, 117, 34, 235, 174, 33, 158, 171],
    [9, 246, 31, 141, 156, 214, 94, 106, 12, 37, 128, 135, 196, 133, 182, 41, 53, 65, 54, 78, 66, 189, 151, 178, 215, 147, 101, 128, 200, 170, 60, 84],
    [47, 82, 30, 42, 125, 11, 216, 18, 203, 192, 53, 244, 237, 104, 6, 235, 141, 133, 23, 147, 176, 75, 161, 71, 232, 246, 107, 114, 245, 209, 242, 15],
    [153, 118, 213, 73, 162, 81, 21, 218, 180, 227, 109, 12, 31, 184, 243, 28, 176, 125, 168, 125, 216, 50, 117, 151, 115, 96, 235, 125, 192, 158, 136, 222],
    [204, 6, 22, 230, 28, 189, 110, 142, 94, 52, 233, 251, 45, 50, 15, 55, 222, 145, 88, 32, 32, 111, 86, 150, 195, 31, 31, 189, 36, 170, 22, 222],
    [156, 84, 124, 184, 17, 90, 68, 136, 59, 159, 112, 186, 104, 247, 81, 23, 205, 85, 53, 156, 146, 97, 24, 117, 227, 134, 248, 175, 152, 193, 114, 171],
    [105, 19, 201, 199, 253, 66, 254, 35, 223, 139, 107, 205, 77, 186, 241, 193, 119, 72, 148, 141, 151, 242, 152, 11, 67, 35, 25, 195, 158, 221, 207, 108],
    [58, 84, 252, 12, 188, 11, 14, 244, 139, 101, 7, 183, 120, 128, 150, 35, 93, 16, 41, 45, 211, 174, 36, 226, 47, 90, 160, 98, 212, 249, 134, 74],
    [97, 198, 11, 72, 125, 26, 146, 30, 11, 204, 155, 248, 83, 221, 160, 251, 21, 155, 48, 191, 87, 178, 226, 210, 199, 83, 176, 11, 225, 91, 90, 9],
    [59, 163, 245, 244, 59, 146, 96, 38, 131, 193, 154, 238, 98, 162, 3, 66, 176, 132, 221, 89, 113, 221, 211, 56, 8, 216, 26, 50, 136, 121, 165, 71],
    [133, 39, 133, 200, 5, 199, 126, 113, 162, 35, 64, 165, 78, 157, 149, 147, 62, 212, 145, 33, 231, 210, 191, 60, 45, 53, 136, 84, 188, 19, 89, 234],
    [162, 124, 137, 108, 72, 89, 32, 72, 67, 22, 106, 246, 111, 14, 144, 43, 156, 59, 62, 214, 210, 253, 19, 212, 53, 171, 192, 32, 6, 92, 82, 111],
    [98, 147, 98, 175, 198, 44, 116, 73, 124, 174, 210, 39, 46, 48, 248, 18, 94, 205, 9, 101, 248, 216, 215, 207, 196, 226, 96, 247, 248, 221, 49, 157],
    [34, 193, 210, 75, 205, 3, 233, 174, 233, 131, 46, 252, 205, 109, 166, 19, 252, 112, 39, 147, 23, 142, 95, 18, 201, 69, 199, 182, 125, 221, 169, 51],
    [33, 236, 5, 91, 56, 206, 117, 156, 212, 208, 244, 119, 233, 189, 236, 44, 91, 129, 153, 148, 93, 180, 67, 155, 174, 51, 74, 150, 77, 246, 36, 108],
    [54, 90, 156, 62, 44, 42, 240, 165, 110, 71, 169, 218, 197, 28, 44, 83, 129, 191, 143, 65, 39, 59, 173, 49, 117, 224, 230, 25, 18, 106, 208, 135],
    [180, 213, 229, 110, 146, 155, 164, 205, 163, 73, 233, 39, 78, 54, 3, 208, 190, 36, 107, 130, 1, 107, 202, 32, 243, 99, 150, 60, 95, 45, 104, 69],
    [227, 60, 223, 156, 127, 113, 32, 185, 142, 140, 120, 64, 137, 83, 224, 127, 46, 205, 24, 48, 6, 181, 96, 109, 243, 73, 180, 194, 18, 172, 244, 62],
    [192, 248, 189, 77, 188, 43, 12, 3, 16, 124, 28, 55, 145, 63, 42, 117, 1, 245, 33, 70, 127, 69, 221, 15, 239, 105, 88, 233, 164, 105, 39, 25],
    [122, 83, 134, 7, 253, 170, 185, 41, 105, 149, 146, 159, 69, 21, 101, 187, 184, 20, 46, 24, 68, 17, 115, 34, 170, 253, 43, 61, 118, 176, 26, 255],
    [102, 211, 79, 186, 113, 248, 244, 80, 247, 228, 85, 152, 133, 62, 83, 191, 194, 59, 189, 18, 144, 39, 203, 177, 49, 162, 244, 255, 215, 135, 140, 208],
    [22, 132, 152, 119, 198, 194, 30, 240, 191, 166, 142, 79, 103, 71, 48, 13, 219, 23, 27, 23, 11, 159, 0, 225, 137, 237, 196, 194, 252, 77, 185, 62],
    [82, 120, 158, 52, 35, 183, 43, 238, 184, 152, 69, 106, 79, 73, 102, 46, 70, 176, 203, 185, 96, 120, 76, 94, 244, 177, 57, 157, 50, 126, 124, 39],
    [102, 67, 17, 12, 86, 40, 255, 245, 158, 223, 118, 216, 45, 91, 245, 115, 191, 128, 15, 22, 164, 214, 93, 251, 30, 93, 111, 26, 70, 41, 109, 11],
    [17, 234, 237, 147, 44, 108, 111, 221, 252, 46, 252, 57, 78, 96, 159, 172, 244, 171, 232, 20, 252, 97, 128, 208, 59, 20, 252, 225, 58, 7, 208, 229],
    [151, 218, 172, 14, 233, 153, 141, 252, 173, 108, 156, 9, 112, 218, 92, 164, 17, 200, 98, 51, 169, 68, 194, 91, 71, 86, 111, 106, 123, 193, 221, 213],
    [143, 155, 236, 106, 98, 221, 40, 235, 211, 109, 18, 39, 116, 85, 146, 222, 102, 88, 179, 105, 116, 163, 187, 152, 164, 197, 130, 246, 131, 234, 108, 66],
    [22, 11, 78, 67, 62, 56, 78, 5, 229, 55, 220, 89, 180, 103, 247, 203, 36, 3, 240, 33, 77, 177, 92, 93, 181, 136, 98, 163, 241, 21, 109, 46],
    [191, 197, 254, 14, 54, 1, 82, 202, 152, 197, 15, 171, 78, 215, 227, 7, 140, 23, 222, 188, 41, 23, 116, 13, 80, 0, 145, 59, 104, 108, 161, 41],
    [108, 27, 61, 199, 167, 6, 185, 220, 129, 53, 42, 103, 22, 185, 198, 102, 198, 8, 216, 98, 98, 114, 198, 75, 145, 74, 176, 85, 114, 252, 110, 132],
    [171, 227, 70, 167, 37, 159, 201, 11, 76, 39, 24, 84, 25, 98, 142, 94, 106, 246, 70, 107, 26, 233, 181, 68, 108, 172, 75, 252, 38, 207, 5, 196],
    [163, 240, 27, 105, 57, 37, 97, 39, 88, 42, 200, 174, 159, 180, 122, 56, 42, 36, 70, 128, 128, 106, 63, 97, 58, 17, 136, 81, 193, 202, 29, 71],
    [159, 67, 144, 248, 211, 12, 45, 217, 46, 201, 240, 149, 182, 94, 43, 154, 233, 176, 169, 37, 165, 37, 142, 36, 28, 159, 30, 145, 15, 115, 67, 24],
    [179, 84, 57, 164, 172, 111, 9, 72, 182, 214, 249, 227, 198, 175, 15, 95, 89, 12, 226, 15, 27, 222, 112, 144, 239, 121, 112, 104, 110, 198, 115, 138],
    [241, 59, 45, 114, 70, 89, 235, 59, 244, 127, 45, 214, 175, 26, 204, 200, 123, 129, 240, 159, 89, 242, 183, 94, 92, 11, 237, 101, 137, 223, 232, 198],
    [213, 192, 57, 183, 72, 170, 100, 102, 87, 130, 151, 78, 195, 220, 48, 37, 192, 66, 237, 245, 77, 205, 194, 181, 222, 49, 56, 91, 9, 76, 182, 120],
    [17, 27, 178, 97, 39, 122, 253, 101, 240, 116, 75, 36, 124, 211, 228, 125, 56, 109, 113, 86, 61, 14, 217, 149, 81, 120, 7, 213, 235, 212, 251, 163],
    [17, 238, 57, 18, 17, 198, 37, 100, 96, 182, 237, 55, 89, 87, 250, 221, 128, 97, 202, 251, 179, 29, 175, 150, 125, 184, 117, 174, 189, 90, 170, 212],
    [53, 213, 252, 23, 207, 187, 173, 208, 15, 94, 113, 10, 218, 57, 241, 148, 197, 173, 124, 118, 106, 214, 112, 114, 36, 95, 31, 173, 69, 240, 245, 48],
    [245, 6, 137, 140, 199, 194, 224, 146, 249, 235, 159, 173, 174, 123, 165, 3, 131, 245, 180, 106, 42, 79, 229, 89, 125, 187, 85, 58, 120, 152, 18, 104],
    [125, 62, 116, 160, 93, 125, 177, 91, 206, 74, 217, 236, 6, 88, 234, 152, 227, 240, 110, 238, 207, 22, 180, 198, 255, 242, 218, 69, 125, 220, 47, 52],
    [255, 224, 84, 254, 122, 224, 203, 109, 198, 92, 58, 249, 182, 29, 82, 9, 244, 57, 133, 29, 180, 61, 11, 165, 153, 115, 55, 223, 21, 70, 104, 235],
    [99, 83, 97, 196, 139, 185, 234, 177, 65, 152, 231, 110, 168, 171, 127, 26, 65, 104, 93, 106, 214, 42, 169, 20, 109, 48, 29, 79, 23, 235, 10, 224],
    [172, 19, 127, 206, 73, 131, 124, 124, 41, 69, 246, 22, 13, 60, 14, 103, 158, 111, 64, 7, 8, 80, 66, 10, 34, 188, 16, 224, 105, 44, 189, 199],
    [97, 22, 192, 159, 137, 113, 142, 130, 159, 105, 183, 175, 177, 217, 214, 12, 105, 115, 147, 93, 150, 179, 50, 19, 228, 210, 134, 137, 254, 16, 142, 231],
    [87, 76, 97, 229, 242, 170, 211, 110, 197, 40, 236, 244, 198, 222, 68, 121, 63, 157, 171, 6, 179, 141, 28, 90, 65, 248, 169, 214, 75, 78, 213, 59],
    [239, 94, 212, 110, 237, 32, 2, 25, 23, 36, 219, 87, 179, 52, 69, 120, 137, 201, 173, 79, 62, 112, 39, 205, 215, 221, 65, 52, 13, 183, 93, 17],
    [107, 213, 229, 3, 72, 85, 161, 18, 65, 240, 222, 232, 252, 114, 133, 15, 253, 153, 85, 178, 131, 71, 168, 100, 40, 181, 250, 25, 17, 159, 106, 208],
    [238, 250, 76, 251, 234, 121, 64, 12, 47, 66, 57, 225, 247, 2, 224, 46, 190, 206, 118, 31, 120, 182, 163, 92, 157, 44, 22, 122, 121, 249, 87, 12],
    [214, 99, 4, 182, 24, 3, 101, 228, 124, 133, 143, 108, 132, 211, 218, 6, 92, 175, 75, 51, 80, 201, 244, 82, 119, 161, 175, 130, 227, 219, 176, 85],
    [14, 5, 142, 63, 125, 4, 57, 249, 5, 77, 89, 199, 53, 88, 122, 233, 150, 85, 246, 71, 58, 35, 76, 228, 148, 216, 43, 85, 134, 247, 234, 198],
    [246, 56, 53, 157, 13, 184, 96, 207, 48, 203, 94, 103, 68, 152, 105, 56, 199, 1, 83, 4, 62, 254, 138, 52, 131, 84, 178, 117, 216, 126, 206, 116],
    [138, 248, 129, 188, 136, 137, 91, 217, 216, 206, 169, 117, 167, 208, 109, 192, 39, 93, 157, 185, 213, 127, 19, 130, 22, 147, 107, 101, 232, 176, 100, 137],
    [248, 184, 171, 166, 82, 229, 179, 205, 230, 188, 116, 188, 183, 191, 241, 82, 137, 162, 34, 207, 219, 119, 89, 169, 128, 157, 192, 133, 116, 145, 31, 96],
    [188, 25, 185, 211, 85, 65, 26, 78, 61, 52, 38, 245, 211, 155, 252, 154, 133, 108, 165, 240, 66, 188, 58, 70, 133, 114, 8, 0, 134, 173, 19, 132],
    [211, 71, 113, 113, 214, 248, 10, 2, 182, 65, 85, 56, 253, 213, 130, 20, 73, 16, 201, 184, 72, 43, 152, 42, 27, 98, 180, 65, 242, 29, 200, 25],
    [218, 167, 107, 77, 22, 103, 153, 87, 131, 50, 38, 168, 132, 69, 6, 9, 138, 55, 186, 201, 73, 121, 241, 203, 252, 108, 74, 195, 176, 155, 155, 96],
    [15, 69, 232, 88, 251, 196, 23, 108, 223, 78, 65, 31, 136, 40, 30, 222, 252, 57, 10, 229, 175, 231, 223, 15, 68, 205, 146, 151, 240, 166, 69, 128],
    [140, 72, 40, 13, 87, 251, 136, 241, 97, 173, 243, 77, 159, 89, 125, 147, 202, 50, 183, 237, 252, 210, 59, 42, 254, 100, 195, 120, 155, 63, 120, 85],
    [245, 133, 67, 89, 129, 156, 220, 244, 78, 23, 231, 110, 184, 0, 206, 55, 215, 115, 62, 187, 145, 147, 117, 97, 149, 115, 31, 33, 150, 77, 49, 161],
    [225, 78, 255, 51, 16, 186, 187, 125, 99, 147, 62, 129, 57, 131, 59, 95, 47, 10, 62, 200, 10, 11, 208, 30, 222, 222, 151, 243, 193, 237, 213, 43],
    [245, 71, 80, 34, 254, 182, 152, 112, 41, 91, 156, 30, 120, 197, 164, 145, 147, 116, 6, 29, 83, 69, 22, 120, 21, 128, 24, 121, 249, 49, 235, 176],
    [132, 46, 245, 48, 182, 221, 140, 81, 23, 111, 217, 93, 153, 69, 223, 58, 117, 101, 6, 170, 140, 74, 53, 250, 104, 187, 94, 31, 161, 74, 202, 100],
    [205, 222, 76, 38, 254, 189, 249, 210, 243, 179, 74, 29, 234, 149, 187, 210, 40, 11, 242, 32, 127, 100, 161, 180, 4, 96, 142, 49, 163, 196, 177, 151],
    [207, 185, 36, 197, 45, 156, 61, 245, 168, 83, 196, 27, 87, 255, 137, 65, 245, 110, 117, 224, 99, 99, 80, 186, 75, 53, 144, 251, 20, 230, 196, 45],
    [151, 83, 141, 134, 97, 232, 215, 92, 143, 197, 159, 122, 117, 155, 27, 174, 179, 203, 246, 202, 40, 43, 144, 1, 111, 167, 108, 192, 90, 54, 230, 216],
    [94, 75, 84, 95, 165, 226, 252, 53, 66, 43, 196, 36, 78, 241, 136, 116, 90, 184, 11, 83, 36, 54, 207, 138, 106, 28, 68, 85, 26, 35, 91, 216],
    [107, 46, 199, 145, 112, 245, 14, 165, 123, 136, 109, 200, 26, 44, 247, 135, 33, 198, 81, 160, 2, 200, 54, 90, 82, 64, 25, 167, 237, 90, 138, 64],
    [155, 159, 231, 240, 164, 140, 43, 154, 235, 112, 250, 8, 40, 193, 7, 128, 161, 89, 126, 24, 246, 113, 235, 40, 78, 15, 178, 225, 28, 154, 123, 168],
    [187, 136, 36, 57, 1, 59, 251, 9, 60, 88, 187, 233, 74, 33, 218, 106, 4, 165, 16, 218, 154, 108, 150, 151, 187, 74, 232, 221, 103, 65, 138, 43],
    [150, 231, 139, 90, 131, 222, 153, 95, 143, 160, 2, 252, 164, 241, 130, 216, 191, 232, 202, 149, 89, 118, 251, 178, 141, 57, 220, 189, 148, 190, 20, 147],
    [133, 9, 74, 56, 101, 26, 7, 2, 7, 115, 100, 131, 173, 161, 125, 152, 41, 138, 128, 18, 92, 0, 92, 116, 213, 137, 151, 191, 93, 42, 198, 144],
    [225, 200, 68, 131, 209, 216, 136, 119, 128, 33, 136, 69, 188, 191, 108, 238, 75, 40, 55, 58, 43, 189, 22, 149, 231, 211, 226, 210, 74, 246, 48, 151],
    [238, 76, 170, 85, 24, 168, 102, 243, 62, 23, 77, 110, 113, 186, 57, 97, 168, 108, 160, 10, 116, 134, 177, 50, 229, 169, 240, 27, 250, 161, 215, 148],
    [42, 44, 96, 254, 150, 175, 172, 145, 81, 212, 189, 147, 47, 219, 69, 190, 44, 126, 23, 94, 2, 176, 89, 132, 38, 202, 193, 92, 56, 81, 28, 180],
    [151, 13, 49, 180, 40, 222, 143, 234, 116, 177, 100, 132, 216, 168, 173, 178, 201, 225, 189, 151, 77, 124, 98, 31, 208, 67, 50, 188, 52, 153, 241, 23],
    [19, 40, 68, 104, 29, 87, 213, 174, 118, 223, 211, 90, 7, 228, 252, 16, 253, 192, 206, 159, 8, 130, 162, 176, 201, 219, 14, 132, 17, 109, 91, 173],
    [40, 22, 89, 120, 136, 228, 160, 211, 163, 107, 130, 184, 51, 22, 171, 50, 104, 14, 184, 240, 15, 140, 211, 185, 4, 214, 129, 36, 109, 40, 90, 14],
    [157, 7, 147, 57, 121, 145, 181, 122, 153, 160, 124, 110, 107, 74, 146, 186, 182, 141, 191, 96, 83, 69, 205, 11, 135, 243, 133, 164, 72, 167, 38, 188],
    [242, 24, 55, 17, 207, 252, 221, 32, 185, 155, 113, 253, 167, 116, 85, 246, 11, 149, 124, 253, 34, 71, 157, 42, 133, 184, 125, 88, 90, 91, 131, 5],
    [225, 213, 109, 197, 180, 161, 164, 244, 126, 23, 166, 228, 41, 221, 198, 173, 186, 113, 37, 107, 164, 129, 93, 243, 233, 122, 212, 175, 13, 251, 77, 177],
    [65, 229, 201, 32, 193, 33, 20, 88, 139, 142, 92, 205, 242, 109, 137, 26, 105, 103, 254, 254, 183, 126, 27, 26, 47, 75, 127, 181, 146, 82, 22, 198],
    [99, 21, 74, 76, 130, 185, 156, 123, 9, 192, 16, 217, 113, 56, 236, 234, 91, 162, 199, 225, 118, 232, 180, 104, 87, 206, 67, 120, 182, 242, 88, 116],
    [93, 92, 143, 182, 182, 20, 147, 36, 142, 24, 67, 239, 143, 185, 135, 95, 242, 139, 146, 7, 94, 110, 184, 126, 21, 60, 175, 70, 152, 189, 172, 195],
    [62, 36, 83, 28, 218, 165, 149, 171, 86, 249, 118, 185, 108, 26, 29, 248, 0, 158, 171, 236, 48, 10, 90, 2, 97, 192, 228, 79, 71, 164, 59, 137],
    [12, 239, 13, 168, 28, 139, 121, 207, 177, 63, 149, 195, 121, 165, 182, 57, 38, 98, 227, 98, 61, 222, 91, 204, 91, 243, 58, 1, 17, 53, 108, 14],
    [56, 159, 41, 242, 223, 169, 64, 158, 233, 23, 110, 198, 86, 93, 138, 150, 131, 149, 22, 177, 105, 115, 70, 31, 25, 247, 185, 216, 199, 58, 130, 37],
    [145, 200, 116, 146, 196, 43, 166, 212, 1, 9, 158, 13, 124, 144, 147, 4, 227, 22, 81, 13, 254, 75, 110, 26, 128, 27, 204, 72, 150, 62, 97, 203],
    [99, 116, 247, 50, 8, 133, 68, 115, 130, 127, 111, 106, 63, 67, 177, 245, 62, 170, 59, 130, 194, 28, 26, 109, 105, 162, 17, 11, 42, 121, 186, 173],
    [245, 67, 83, 0, 138, 37, 83, 38, 46, 205, 196, 163, 71, 73, 86, 59, 160, 149, 14, 139, 15, 200, 101, 39, 128, 176, 166, 20, 185, 150, 131, 193],
    [186, 2, 115, 26, 230, 149, 170, 229, 205, 73, 180, 157, 132, 51, 11, 99, 153, 87, 51, 235, 34, 16, 42, 202, 117, 95, 1, 121, 177, 224, 226, 15],
    [108, 183, 80, 178, 24, 22, 6, 81, 31, 74, 126, 71, 134, 181, 54, 146, 245, 26, 156, 220, 77, 49, 114, 253, 207, 185, 38, 122, 236, 167, 228, 228],
    [100, 65, 14, 101, 27, 52, 101, 36, 207, 229, 110, 104, 194, 55, 234, 118, 192, 55, 121, 33, 105, 112, 39, 235, 121, 74, 6, 117, 1, 251, 41, 16],
    [156, 170, 168, 51, 201, 50, 115, 249, 39, 180, 20, 95, 134, 164, 23, 145, 234, 110, 57, 163, 29, 17, 138, 106, 174, 61, 188, 218, 172, 95, 132, 172],
    [228, 244, 225, 122, 45, 8, 190, 169, 246, 20, 238, 226, 119, 201, 190, 29, 227, 198, 196, 185, 10, 144, 82, 95, 126, 4, 147, 229, 60, 92, 77, 112],
    [135, 157, 196, 240, 91, 25, 235, 195, 176, 55, 244, 104, 54, 51, 223, 19, 50, 176, 84, 207, 82, 250, 55, 45, 50, 60, 66, 28, 184, 147, 162, 170],
    [49, 235, 165, 28, 49, 58, 92, 8, 34, 106, 223, 24, 212, 163, 89, 207, 223, 216, 210, 232, 22, 177, 63, 74, 249, 82, 247, 234, 101, 132, 220, 251],
    [47, 61, 51, 84, 50, 199, 11, 88, 10, 240, 232, 225, 179, 103, 74, 124, 2, 13, 104, 58, 165, 247, 58, 170, 237, 253, 197, 90, 249, 4, 194, 28],
    [233, 97, 83, 32, 18, 140, 199, 163, 214, 7, 142, 154, 240, 86, 3, 24, 142, 92, 203, 240, 208, 125, 139, 115, 93, 61, 245, 232, 224, 193, 40, 31],
    [207, 108, 54, 140, 4, 194, 57, 204, 22, 136, 165, 163, 179, 159, 148, 165, 92, 229, 183, 99, 30, 2, 127, 192, 19, 143, 5, 72, 24, 156, 98, 250],
    [102, 117, 186, 120, 6, 72, 200, 80, 108, 176, 2, 200, 102, 33, 249, 211, 63, 128, 147, 225, 37, 65, 198, 144, 168, 211, 38, 28, 71, 201, 43, 204],
    [156, 30, 214, 10, 99, 55, 175, 125, 22, 89, 51, 158, 249, 93, 204, 183, 201, 26, 85, 185, 234, 171, 52, 147, 65, 167, 249, 113, 152, 238, 229, 25],
    [168, 225, 160, 243, 92, 21, 192, 26, 69, 139, 203, 52, 85, 40, 183, 81, 85, 108, 20, 133, 15, 111, 155, 220, 201, 147, 59, 128, 3, 210, 155, 67],
    [54, 188, 249, 41, 37, 137, 254, 110, 163, 232, 47, 239, 227, 170, 177, 184, 202, 139, 131, 71, 234, 90, 20, 178, 62, 71, 14, 203, 58, 215, 197, 123],
    [197, 126, 146, 120, 175, 120, 250, 60, 171, 56, 102, 123, 239, 76, 226, 157, 120, 55, 135, 162, 247, 49, 212, 225, 34, 0, 39, 15, 12, 50, 50, 10],
    [104, 54, 207, 19, 186, 196, 0, 233, 16, 80, 113, 205, 106, 244, 112, 132, 223, 172, 173, 78, 94, 48, 44, 148, 191, 237, 36, 224, 19, 175, 183, 62],
    [193, 44, 176, 36, 162, 229, 85, 28, 202, 14, 8, 252, 232, 241, 197, 227, 20, 85, 92, 195, 254, 246, 50, 158, 233, 148, 163, 219, 117, 33, 102, 174],
    [30, 60, 79, 71, 80, 200, 194, 155, 191, 169, 206, 211, 23, 120, 129, 118, 177, 86, 211, 66, 229, 127, 119, 119, 246, 47, 215, 34, 26, 68, 49, 47],
    [60, 41, 114, 80, 133, 192, 228, 134, 40, 39, 22, 176, 234, 167, 20, 199, 177, 172, 251, 62, 91, 194, 159, 225, 90, 67, 2, 176, 38, 241, 33, 148],
    [148, 156, 15, 12, 49, 107, 72, 5, 241, 198, 202, 143, 142, 81, 173, 6, 98, 107, 153, 70, 29, 200, 210, 17, 146, 103, 173, 167, 109, 220, 242, 52],
    [216, 218, 162, 149, 130, 177, 66, 26, 48, 238, 8, 36, 147, 182, 200, 47, 17, 226, 0, 84, 154, 193, 105, 220, 55, 120, 91, 120, 94, 191, 79, 12],
    [54, 60, 98, 107, 43, 232, 138, 255, 71, 183, 106, 243, 201, 144, 50, 120, 154, 32, 171, 133, 28, 190, 4, 53, 157, 169, 240, 77, 149, 55, 27, 65],
    [223, 165, 141, 253, 114, 243, 199, 8, 13, 2, 73, 167, 117, 143, 211, 99, 104, 114, 246, 63, 162, 75, 24, 71, 62, 211, 111, 3, 30, 36, 131, 71],
    [111, 14, 68, 185, 206, 78, 166, 29, 82, 163, 71, 156, 16, 246, 14, 249, 22, 147, 127, 121, 159, 17, 150, 75, 127, 28, 119, 113, 6, 57, 5, 196],
    [182, 220, 45, 166, 120, 192, 101, 235, 220, 227, 116, 235, 225, 132, 39, 40, 39, 114, 3, 238, 26, 154, 41, 131, 47, 5, 140, 240, 19, 213, 173, 133],
    [210, 197, 219, 57, 42, 24, 80, 169, 5, 245, 174, 154, 243, 166, 227, 236, 253, 27, 187, 14, 240, 109, 91, 97, 141, 39, 130, 33, 187, 122, 109, 40],
    [212, 158, 51, 124, 93, 213, 69, 130, 39, 195, 110, 238, 100, 255, 174, 171, 143, 216, 204, 67, 57, 89, 153, 170, 189, 243, 139, 64, 187, 72, 149, 71],
    [192, 148, 237, 47, 97, 74, 183, 160, 46, 117, 87, 248, 235, 166, 176, 59, 69, 124, 231, 190, 172, 241, 216, 3, 16, 136, 249, 122, 23, 112, 229, 230],
    [110, 129, 110, 196, 45, 219, 123, 175, 141, 198, 116, 182, 38, 168, 88, 187, 255, 175, 118, 182, 244, 60, 75, 122, 201, 76, 130, 201, 88, 140, 150, 59],
    [75, 11, 0, 179, 49, 64, 172, 234, 108, 150, 52, 161, 30, 59, 117, 28, 210, 241, 78, 96, 132, 138, 194, 177, 107, 82, 72, 197, 177, 159, 47, 166],
    [43, 211, 246, 239, 171, 94, 135, 26, 40, 211, 118, 50, 233, 124, 216, 61, 250, 254, 152, 34, 254, 222, 250, 11, 245, 75, 83, 212, 134, 207, 235, 56],
    [183, 29, 243, 178, 206, 119, 162, 226, 215, 143, 122, 123, 145, 191, 136, 104, 182, 27, 224, 232, 161, 45, 48, 11, 19, 0, 177, 64, 215, 250, 218, 19],
    [161, 177, 134, 175, 198, 20, 148, 145, 15, 10, 144, 98, 27, 174, 252, 74, 92, 15, 77, 174, 171, 132, 163, 68, 181, 17, 170, 38, 164, 56, 20, 202],
    [145, 91, 218, 43, 32, 134, 1, 165, 253, 81, 230, 173, 99, 218, 229, 6, 105, 3, 130, 39, 136, 77, 6, 86, 72, 167, 226, 103, 127, 135, 177, 207],
    [115, 136, 53, 109, 91, 41, 85, 230, 198, 78, 70, 81, 84, 232, 97, 182, 19, 222, 30, 170, 95, 206, 195, 224, 129, 75, 200, 36, 1, 62, 120, 223],
    [122, 54, 176, 66, 47, 220, 177, 61, 103, 12, 242, 216, 199, 19, 88, 69, 134, 39, 189, 24, 30, 131, 67, 108, 185, 86, 114, 121, 168, 201, 226, 42],
    [11, 163, 222, 157, 194, 178, 173, 23, 25, 211, 51, 230, 187, 27, 19, 167, 13, 253, 246, 255, 3, 12, 209, 13, 60, 245, 125, 128, 40, 166, 47, 79],
    [117, 149, 175, 130, 174, 47, 165, 156, 217, 191, 59, 68, 5, 211, 28, 105, 185, 141, 231, 31, 237, 89, 69, 253, 119, 125, 138, 179, 179, 147, 168, 95],
    [84, 22, 213, 141, 9, 149, 234, 212, 11, 23, 50, 191, 248, 222, 229, 151, 218, 89, 150, 186, 174, 46, 35, 115, 206, 113, 105, 135, 182, 119, 238, 114],
    [224, 48, 19, 64, 12, 11, 221, 216, 62, 109, 125, 20, 206, 40, 195, 236, 216, 175, 208, 42, 120, 150, 81, 245, 77, 127, 66, 115, 220, 5, 40, 235],
    [30, 97, 19, 225, 100, 248, 65, 203, 131, 165, 161, 204, 104, 5, 225, 231, 109, 54, 112, 154, 75, 109, 99, 129, 167, 184, 246, 26, 105, 166, 56, 89],
    [216, 114, 40, 93, 58, 89, 9, 146, 217, 197, 228, 0, 89, 124, 177, 220, 61, 3, 240, 176, 38, 88, 120, 132, 81, 122, 4, 70, 147, 252, 115, 118],
    [48, 24, 167, 82, 153, 204, 90, 155, 49, 4, 98, 171, 64, 185, 125, 71, 253, 124, 137, 255, 97, 205, 111, 237, 117, 34, 5, 32, 177, 9, 247, 60],
    [177, 62, 148, 250, 146, 115, 15, 168, 176, 168, 68, 244, 57, 104, 92, 203, 196, 173, 215, 146, 251, 124, 100, 101, 85, 140, 185, 193, 212, 228, 38, 129],
    [85, 196, 59, 36, 97, 204, 71, 175, 45, 13, 105, 238, 15, 197, 117, 14, 165, 190, 0, 243, 118, 98, 109, 222, 121, 32, 244, 208, 137, 117, 57, 87],
    [33, 229, 193, 134, 214, 146, 198, 33, 195, 66, 159, 131, 20, 56, 88, 45, 176, 181, 212, 178, 55, 252, 9, 155, 196, 25, 157, 163, 54, 215, 255, 158],
    [4, 51, 80, 19, 12, 170, 233, 142, 14, 233, 229, 166, 162, 100, 145, 37, 86, 25, 26, 204, 105, 98, 199, 119, 213, 87, 34, 38, 150, 132, 181, 180],
    [191, 24, 180, 59, 97, 101, 43, 93, 115, 244, 30, 191, 61, 114, 229, 228, 58, 235, 245, 7, 111, 73, 125, 222, 49, 234, 61, 233, 222, 73, 152, 239],
    [22, 104, 235, 79, 173, 83, 186, 123, 55, 178, 51, 188, 184, 25, 244, 160, 195, 142, 226, 166, 208, 62, 32, 65, 52, 237, 204, 136, 43, 181, 106, 232],
    [94, 167, 52, 36, 49, 27, 235, 141, 34, 182, 254, 194, 177, 49, 116, 184, 253, 181, 13, 214, 209, 200, 148, 125, 254, 58, 57, 203, 237, 187, 50, 167],
    [238, 191, 89, 167, 98, 85, 208, 4, 101, 0, 83, 73, 221, 87, 73, 212, 28, 160, 181, 50, 92, 170, 101, 159, 92, 169, 254, 66, 115, 182, 62, 106],
    [243, 45, 87, 42, 63, 148, 132, 188, 150, 156, 236, 49, 164, 227, 139, 26, 205, 168, 175, 30, 77, 243, 39, 93, 242, 154, 234, 147, 161, 101, 187, 237],
    [228, 71, 88, 181, 219, 163, 125, 33, 254, 93, 250, 49, 75, 6, 49, 205, 96, 138, 212, 174, 75, 200, 107, 112, 77, 35, 182, 5, 176, 99, 210, 193],
    [245, 99, 158, 47, 245, 234, 146, 144, 93, 71, 201, 178, 155, 195, 253, 152, 20, 47, 83, 2, 127, 215, 129, 135, 27, 156, 2, 27, 251, 1, 24, 64],
    [63, 234, 194, 184, 178, 52, 172, 216, 145, 178, 134, 0, 166, 30, 9, 170, 136, 200, 212, 19, 46, 240, 205, 206, 68, 172, 76, 187, 152, 129, 237, 138],
    [23, 9, 12, 180, 94, 178, 247, 150, 55, 247, 144, 55, 49, 46, 127, 230, 208, 169, 4, 40, 124, 51, 223, 128, 78, 116, 225, 157, 193, 218, 95, 80],
    [66, 162, 79, 237, 89, 146, 151, 101, 181, 216, 49, 230, 182, 100, 167, 49, 6, 114, 38, 6, 191, 203, 242, 60, 112, 53, 47, 96, 29, 40, 90, 50],
    [95, 47, 99, 142, 89, 62, 162, 48, 104, 170, 121, 252, 66, 179, 42, 222, 178, 7, 197, 148, 121, 220, 62, 45, 215, 94, 12, 23, 187, 123, 14, 244],
    [71, 180, 21, 48, 207, 247, 180, 129, 5, 149, 148, 56, 199, 51, 83, 79, 183, 208, 149, 214, 242, 104, 141, 255, 109, 35, 212, 100, 44, 215, 150, 105],
    [239, 120, 188, 140, 214, 42, 141, 204, 143, 150, 45, 63, 170, 204, 226, 140, 250, 171, 83, 188, 86, 117, 242, 151, 65, 242, 45, 6, 63, 47, 95, 58],
    [120, 197, 204, 113, 230, 25, 159, 32, 41, 36, 95, 144, 178, 17, 130, 177, 174, 179, 181, 210, 190, 149, 251, 26, 18, 63, 199, 254, 176, 161, 206, 118],
    [214, 158, 83, 7, 217, 73, 210, 237, 194, 90, 116, 122, 44, 15, 157, 157, 234, 243, 65, 200, 78, 27, 160, 251, 72, 1, 114, 32, 189, 122, 144, 162],
    [1, 27, 73, 220, 104, 145, 142, 153, 54, 37, 204, 47, 116, 39, 248, 115, 190, 108, 3, 49, 96, 75, 48, 197, 161, 182, 27, 209, 138, 145, 185, 11],
    [78, 133, 136, 0, 68, 37, 127, 155, 105, 161, 54, 129, 21, 210, 242, 217, 148, 12, 198, 215, 103, 246, 221, 104, 206, 205, 243, 140, 135, 234, 53, 112],
    [30, 0, 132, 11, 150, 184, 95, 136, 71, 228, 203, 201, 169, 101, 196, 186, 201, 216, 214, 60, 159, 91, 4, 24, 151, 46, 104, 160, 114, 179, 239, 193],
    [202, 173, 75, 47, 187, 131, 15, 165, 64, 2, 161, 103, 95, 21, 153, 217, 176, 146, 205, 57, 138, 214, 251, 184, 22, 191, 232, 249, 72, 205, 214, 32],
    [243, 19, 105, 113, 145, 60, 56, 114, 196, 181, 54, 182, 216, 153, 8, 247, 182, 55, 27, 6, 83, 33, 63, 20, 44, 117, 122, 1, 114, 40, 40, 199],
    [214, 26, 96, 10, 124, 111, 125, 194, 194, 191, 144, 245, 111, 6, 29, 246, 91, 126, 204, 149, 195, 126, 196, 221, 133, 119, 98, 84, 186, 133, 120, 210],
    [156, 228, 229, 138, 142, 19, 20, 191, 20, 202, 138, 82, 172, 32, 250, 27, 30, 39, 167, 140, 64, 162, 75, 90, 40, 116, 34, 249, 146, 178, 155, 157],
    [64, 191, 99, 213, 68, 204, 92, 197, 246, 35, 150, 121, 58, 253, 110, 155, 81, 17, 76, 90, 57, 169, 234, 96, 139, 66, 92, 83, 160, 218, 22, 205],
    [168, 141, 68, 162, 148, 10, 58, 47, 195, 99, 48, 73, 38, 210, 99, 191, 39, 26, 251, 86, 43, 171, 86, 64, 203, 14, 129, 245, 232, 67, 32, 163],
    [139, 27, 121, 103, 206, 245, 178, 242, 3, 107, 37, 198, 163, 147, 227, 123, 215, 116, 167, 203, 222, 123, 231, 155, 180, 67, 210, 107, 240, 169, 12, 134],
    [16, 68, 157, 21, 138, 95, 203, 144, 112, 251, 67, 171, 219, 53, 105, 147, 135, 152, 93, 189, 173, 36, 209, 247, 232, 18, 135, 213, 198, 18, 113, 137],
    [200, 105, 53, 109, 58, 62, 107, 23, 132, 227, 133, 236, 25, 228, 146, 54, 16, 9, 114, 229, 116, 71, 5, 127, 106, 27, 86, 44, 154, 144, 16, 202],
    [238, 26, 242, 82, 208, 199, 178, 35, 54, 242, 159, 132, 97, 162, 127, 183, 10, 56, 80, 231, 9, 231, 105, 181, 4, 2, 209, 168, 189, 161, 238, 3],
    [81, 102, 37, 119, 214, 77, 237, 84, 171, 95, 144, 234, 146, 59, 93, 244, 160, 29, 92, 202, 184, 13, 90, 53, 20, 201, 114, 162, 99, 209, 29, 28],
    [143, 149, 201, 120, 219, 135, 30, 63, 245, 219, 34, 213, 227, 199, 194, 114, 18, 214, 49, 15, 213, 118, 129, 146, 223, 196, 35, 172, 68, 32, 10, 113],
    [9, 184, 124, 60, 126, 56, 119, 50, 137, 90, 196, 77, 81, 227, 117, 64, 232, 161, 29, 167, 86, 60, 113, 156, 216, 29, 52, 141, 146, 201, 107, 71],
    [49, 24, 52, 221, 186, 254, 32, 103, 125, 221, 191, 159, 75, 235, 43, 91, 11, 158, 110, 233, 125, 221, 183, 15, 206, 78, 143, 98, 193, 183, 81, 141],
    [124, 238, 36, 98, 141, 41, 12, 22, 24, 53, 50, 113, 108, 197, 168, 168, 137, 188, 149, 27, 75, 10, 21, 7, 195, 43, 142, 41, 206, 224, 16, 82],
    [51, 249, 58, 152, 121, 239, 24, 249, 119, 145, 80, 178, 219, 172, 230, 248, 204, 23, 178, 158, 26, 246, 190, 78, 16, 72, 252, 100, 116, 137, 241, 194],
    [170, 115, 177, 58, 81, 171, 44, 169, 115, 57, 87, 68, 132, 57, 146, 113, 21, 237, 138, 251, 161, 226, 222, 240, 121, 46, 181, 14, 182, 141, 22, 85],
    [31, 130, 193, 172, 201, 236, 75, 204, 152, 137, 80, 211, 146, 236, 5, 191, 26, 254, 90, 66, 100, 47, 132, 220, 141, 64, 106, 181, 127, 158, 18, 133],
    [150, 184, 100, 238, 158, 16, 163, 31, 132, 37, 8, 78, 209, 21, 223, 137, 81, 187, 141, 19, 3, 203, 19, 244, 60, 10, 96, 14, 176, 54, 67, 176],
    [58, 146, 9, 154, 143, 174, 89, 55, 29, 62, 123, 253, 139, 150, 142, 6, 144, 192, 173, 152, 165, 129, 35, 92, 198, 39, 57, 171, 221, 23, 58, 186],
    [68, 19, 55, 32, 110, 246, 5, 238, 198, 32, 14, 127, 182, 37, 153, 130, 186, 15, 46, 132, 180, 178, 142, 16, 126, 20, 14, 186, 54, 216, 20, 132],
    [96, 4, 132, 120, 174, 71, 237, 215, 239, 24, 241, 35, 90, 253, 37, 74, 114, 255, 175, 50, 196, 188, 87, 38, 232, 210, 80, 195, 190, 81, 227, 203],
    [194, 169, 8, 217, 143, 93, 249, 135, 173, 228, 27, 95, 206, 33, 48, 103, 239, 188, 194, 30, 242, 36, 2, 18, 164, 30, 84, 181, 231, 194, 138, 229],
    [169, 46, 253, 130, 16, 147, 115, 229, 143, 154, 32, 86, 222, 224, 30, 128, 126, 33, 108, 230, 7, 95, 112, 81, 32, 124, 10, 159, 125, 102, 110, 80],
    [14, 9, 18, 41, 83, 54, 199, 149, 224, 179, 142, 207, 128, 228, 180, 74, 65, 59, 43, 100, 195, 8, 245, 231, 198, 92, 217, 239, 249, 111, 176, 219],
    [94, 43, 12, 112, 20, 220, 126, 55, 192, 166, 157, 121, 252, 228, 186, 15, 87, 103, 60, 97, 84, 32, 70, 150, 0, 134, 84, 100, 242, 191, 190, 96],
    [163, 62, 226, 125, 108, 59, 112, 166, 44, 231, 167, 72, 188, 125, 14, 2, 83, 181, 129, 72, 119, 64, 70, 55, 202, 159, 171, 138, 6, 137, 114, 226],
    [252, 18, 15, 18, 3, 196, 3, 53, 30, 78, 34, 157, 86, 37, 83, 153, 85, 166, 206, 230, 225, 212, 11, 183, 167, 43, 43, 112, 127, 39, 194, 153],
    [242, 210, 127, 235, 98, 100, 131, 8, 56, 109, 97, 215, 29, 56, 98, 153, 244, 137, 245, 69, 12, 21, 151, 86, 83, 23, 43, 117, 27, 148, 50, 154],
    [234, 132, 101, 72, 17, 228, 154, 119, 199, 51, 180, 196, 189, 208, 177, 162, 152, 196, 140, 223, 194, 245, 172, 130, 82, 153, 41, 18, 194, 250, 188, 155],
    [142, 213, 91, 26, 5, 109, 117, 224, 163, 46, 62, 221, 137, 161, 84, 183, 172, 207, 235, 169, 255, 46, 252, 200, 122, 125, 35, 143, 5, 147, 118, 109],
    [57, 147, 143, 97, 186, 69, 19, 206, 173, 138, 117, 221, 141, 116, 139, 86, 104, 85, 229, 49, 228, 96, 237, 235, 41, 14, 138, 240, 22, 113, 21, 80],
    [178, 202, 99, 149, 12, 53, 14, 20, 236, 150, 190, 204, 230, 217, 69, 28, 78, 222, 50, 213, 56, 173, 39, 202, 17, 138, 159, 23, 132, 28, 113, 17],
    [10, 38, 169, 13, 37, 47, 29, 165, 216, 49, 138, 191, 161, 63, 27, 117, 131, 90, 78, 22, 77, 165, 206, 206, 235, 6, 55, 201, 152, 54, 75, 54],
    [184, 61, 90, 127, 179, 239, 127, 121, 82, 117, 8, 191, 2, 82, 50, 181, 150, 118, 131, 203, 241, 22, 184, 215, 168, 158, 189, 171, 255, 255, 188, 60],
    [230, 152, 32, 65, 180, 0, 31, 3, 50, 94, 170, 214, 70, 79, 92, 138, 16, 111, 22, 17, 106, 219, 179, 71, 228, 137, 156, 97, 119, 108, 117, 184],
    [41, 212, 71, 80, 84, 229, 190, 14, 187, 163, 253, 65, 67, 60, 92, 255, 154, 14, 27, 202, 73, 38, 241, 15, 31, 124, 123, 183, 52, 184, 242, 208],
    [204, 120, 163, 52, 67, 72, 249, 77, 213, 161, 38, 100, 179, 238, 54, 94, 160, 103, 1, 252, 38, 95, 252, 23, 109, 38, 229, 33, 239, 193, 143, 185],
    [63, 7, 242, 44, 109, 64, 149, 254, 119, 219, 37, 191, 41, 248, 121, 249, 53, 104, 160, 41, 60, 8, 213, 122, 55, 54, 73, 80, 178, 252, 4, 202],
    [68, 115, 254, 152, 181, 170, 7, 144, 180, 197, 14, 59, 9, 185, 66, 241, 218, 62, 63, 253, 46, 228, 96, 99, 199, 208, 187, 206, 24, 174, 162, 137],
    [24, 253, 92, 86, 226, 141, 127, 200, 225, 25, 166, 46, 82, 108, 172, 48, 251, 32, 132, 78, 29, 111, 132, 253, 106, 104, 111, 28, 146, 132, 107, 115],
    [70, 251, 131, 197, 142, 123, 22, 168, 65, 153, 3, 233, 104, 34, 17, 206, 114, 180, 182, 189, 27, 142, 29, 57, 99, 59, 60, 124, 247, 131, 95, 161],
    [165, 136, 139, 104, 152, 140, 75, 250, 148, 6, 211, 203, 48, 51, 141, 130, 75, 199, 49, 155, 79, 145, 168, 210, 0, 140, 198, 49, 163, 199, 146, 159],
    [90, 177, 108, 33, 59, 139, 194, 229, 4, 22, 206, 63, 136, 255, 231, 190, 200, 207, 193, 135, 41, 23, 89, 244, 22, 91, 250, 41, 225, 133, 24, 251],
    [206, 239, 245, 171, 106, 123, 209, 92, 147, 0, 146, 220, 30, 102, 213, 175, 242, 14, 212, 223, 110, 22, 71, 205, 156, 157, 107, 157, 85, 134, 4, 98],
    [41, 139, 61, 140, 70, 109, 212, 141, 2, 73, 130, 109, 1, 69, 116, 7, 126, 125, 37, 200, 144, 17, 50, 200, 87, 96, 103, 15, 1, 180, 169, 43],
    [222, 103, 168, 75, 90, 193, 49, 186, 228, 70, 21, 112, 71, 156, 171, 53, 96, 171, 21, 102, 95, 95, 221, 198, 79, 147, 85, 213, 184, 28, 112, 120],
    [145, 220, 142, 137, 141, 216, 166, 253, 146, 174, 14, 163, 122, 168, 209, 154, 243, 78, 15, 244, 133, 174, 226, 122, 39, 109, 113, 191, 53, 163, 63, 129],
    [200, 92, 180, 29, 174, 169, 126, 223, 84, 165, 154, 235, 131, 53, 84, 207, 40, 69, 80, 15, 20, 28, 108, 44, 24, 244, 30, 38, 231, 242, 156, 193],
    [39, 207, 90, 35, 73, 99, 114, 67, 67, 72, 225, 250, 110, 54, 173, 177, 158, 42, 173, 26, 56, 172, 201, 45, 150, 184, 0, 76, 215, 70, 224, 81],
    [205, 53, 203, 148, 157, 174, 110, 26, 150, 155, 91, 79, 130, 89, 171, 111, 119, 239, 47, 89, 155, 128, 33, 157, 108, 76, 181, 217, 217, 158, 153, 243],
    [47, 183, 63, 206, 85, 23, 133, 68, 134, 7, 218, 175, 197, 233, 208, 116, 183, 41, 175, 48, 210, 26, 139, 169, 9, 158, 151, 188, 146, 130, 186, 173],
    [174, 147, 83, 113, 216, 50, 33, 176, 128, 94, 3, 141, 32, 123, 193, 84, 34, 68, 114, 37, 24, 213, 179, 161, 242, 116, 237, 177, 5, 34, 186, 42],
    [236, 25, 18, 105, 13, 162, 217, 255, 203, 230, 76, 150, 97, 121, 193, 228, 222, 171, 8, 96, 30, 80, 169, 2, 225, 234, 229, 133, 156, 181, 225, 60],
    [27, 96, 202, 3, 213, 230, 19, 29, 20, 252, 128, 169, 143, 172, 82, 71, 126, 174, 104, 177, 228, 154, 10, 97, 190, 168, 97, 218, 111, 212, 136, 163],
    [231, 114, 206, 107, 81, 63, 238, 196, 219, 33, 118, 77, 219, 86, 177, 109, 137, 74, 101, 143, 77, 211, 151, 208, 136, 251, 250, 13, 103, 28, 221, 106],
    [1, 136, 47, 87, 37, 5, 109, 208, 183, 18, 87, 126, 29, 133, 171, 254, 4, 39, 124, 254, 163, 15, 210, 15, 215, 217, 156, 216, 157, 98, 214, 134],
    [157, 219, 32, 169, 220, 247, 54, 255, 157, 175, 64, 13, 122, 235, 52, 139, 35, 188, 119, 128, 80, 100, 133, 213, 45, 220, 75, 223, 251, 164, 250, 25],
    [59, 219, 167, 177, 213, 68, 168, 198, 234, 12, 241, 46, 46, 167, 94, 233, 94, 190, 55, 128, 2, 16, 168, 141, 52, 130, 70, 40, 200, 136, 222, 168],
    [3, 244, 63, 120, 80, 73, 40, 37, 196, 8, 246, 153, 93, 58, 225, 37, 10, 58, 152, 183, 157, 133, 141, 255, 59, 150, 209, 58, 120, 185, 211, 92],
    [54, 146, 115, 118, 249, 252, 128, 138, 189, 99, 219, 105, 54, 139, 236, 165, 11, 88, 112, 184, 168, 73, 213, 194, 167, 226, 182, 63, 49, 90, 176, 126],
    [6, 75, 61, 18, 42, 190, 37, 195, 98, 101, 247, 159, 199, 148, 176, 173, 242, 138, 108, 94, 79, 232, 237, 54, 97, 242, 40, 126, 140, 236, 173, 204],
    [155, 48, 67, 144, 92, 167, 149, 86, 172, 177, 210, 209, 47, 154, 76, 11, 237, 140, 237, 43, 209, 168, 46, 124, 223, 38, 116, 48, 105, 190, 83, 227],
    [236, 110, 50, 110, 242, 159, 227, 34, 182, 33, 17, 88, 65, 148, 197, 78, 252, 140, 75, 108, 37, 240, 152, 178, 79, 167, 66, 163, 145, 138, 191, 111],
    [143, 222, 213, 156, 66, 123, 46, 104, 9, 200, 16, 145, 90, 172, 169, 99, 87, 50, 161, 222, 204, 75, 162, 172, 142, 10, 29, 144, 252, 16, 146, 201],
    [10, 72, 69, 247, 138, 27, 73, 67, 115, 50, 132, 158, 170, 204, 2, 22, 233, 94, 29, 67, 153, 242, 74, 172, 6, 251, 81, 25, 33, 220, 152, 27],
    [173, 94, 103, 42, 91, 16, 157, 242, 155, 3, 72, 165, 57, 41, 157, 94, 30, 222, 108, 107, 248, 222, 105, 74, 110, 125, 199, 39, 241, 133, 164, 226],
    [85, 83, 240, 85, 20, 166, 246, 39, 255, 232, 52, 30, 8, 248, 11, 195, 121, 93, 239, 43, 60, 110, 149, 200, 201, 159, 22, 203, 115, 20, 201, 182],
    [147, 79, 56, 18, 172, 41, 134, 134, 46, 213, 100, 215, 222, 93, 42, 26, 61, 116, 199, 111, 154, 208, 179, 46, 179, 37, 20, 241, 87, 156, 51, 138],
    [209, 201, 127, 5, 160, 77, 69, 214, 123, 224, 216, 43, 57, 249, 61, 142, 6, 229, 45, 179, 174, 180, 117, 32, 103, 201, 181, 230, 21, 131, 182, 65],
    [253, 255, 58, 176, 35, 169, 1, 212, 230, 212, 125, 57, 144, 92, 198, 164, 211, 148, 185, 41, 125, 38, 5, 172, 23, 239, 191, 16, 218, 150, 159, 210],
    [210, 205, 184, 183, 8, 250, 47, 247, 40, 163, 232, 178, 20, 55, 241, 138, 233, 145, 238, 196, 235, 184, 112, 62, 255, 227, 234, 233, 37, 66, 209, 71],
    [63, 62, 53, 224, 167, 117, 217, 177, 213, 236, 46, 204, 202, 6, 56, 28, 65, 239, 237, 235, 89, 213, 172, 84, 145, 235, 233, 105, 108, 176, 136, 123],
    [119, 47, 145, 29, 217, 214, 105, 40, 151, 24, 141, 11, 3, 247, 24, 251, 95, 189, 2, 2, 13, 15, 206, 19, 116, 241, 53, 74, 49, 32, 80, 36],
    [3, 170, 245, 119, 55, 23, 254, 174, 111, 112, 75, 242, 99, 122, 224, 169, 175, 139, 27, 38, 195, 73, 62, 242, 149, 83, 129, 131, 120, 119, 58, 4],
    [50, 133, 154, 58, 182, 90, 197, 41, 50, 225, 111, 173, 96, 96, 101, 54, 54, 214, 116, 111, 82, 180, 203, 32, 95, 79, 18, 21, 105, 196, 153, 245],
    [19, 100, 150, 194, 161, 106, 34, 181, 139, 189, 1, 82, 155, 102, 216, 81, 12, 197, 163, 236, 97, 113, 28, 186, 162, 152, 165, 37, 128, 176, 0, 214],
    [176, 243, 50, 62, 122, 60, 173, 138, 230, 119, 131, 64, 204, 42, 23, 174, 12, 179, 28, 129, 141, 243, 118, 124, 218, 124, 61, 212, 35, 114, 94, 144],
    [2, 215, 22, 13, 119, 225, 140, 100, 71, 190, 128, 194, 227, 85, 199, 237, 67, 136, 84, 82, 113, 112, 44, 80, 37, 59, 9, 20, 198, 92, 229, 254],
    [232, 217, 92, 194, 180, 188, 25, 140, 84, 180, 11, 210, 20, 223, 149, 138, 251, 101, 245, 231, 61, 44, 46, 175, 224, 89, 60, 245, 198, 53, 193, 240],
    [30, 187, 218, 179, 53, 224, 84, 1, 95, 15, 193, 127, 98, 119, 6, 9, 114, 61, 146, 198, 64, 182, 91, 169, 151, 77, 102, 108, 54, 74, 58, 99],
    [214, 40, 141, 152, 69, 193, 55, 106, 155, 208, 64, 169, 13, 213, 254, 250, 62, 242, 135, 222, 52, 13, 7, 109, 108, 40, 76, 54, 95, 132, 3, 33],
    [134, 26, 238, 123, 147, 40, 161, 216, 75, 21, 95, 173, 160, 146, 189, 74, 110, 234, 181, 53, 207, 61, 245, 40, 225, 210, 85, 236, 74, 151, 139, 165],
    [137, 18, 42, 38, 217, 124, 48, 117, 175, 111, 235, 56, 66, 206, 125, 14, 104, 105, 54, 105, 122, 198, 83, 61, 138, 172, 95, 104, 208, 83, 86, 99],
    [241, 64, 146, 76, 165, 71, 250, 74, 233, 250, 214, 124, 45, 161, 151, 31, 116, 200, 110, 25, 11, 188, 201, 235, 254, 63, 124, 220, 47, 0, 202, 190],
    [134, 217, 23, 159, 138, 52, 93, 0, 32, 161, 34, 60, 246, 137, 156, 92, 16, 73, 96, 98, 110, 63, 95, 136, 147, 149, 113, 249, 246, 232, 71, 17],
    [139, 227, 201, 151, 74, 4, 11, 154, 63, 95, 23, 95, 204, 100, 220, 207, 115, 196, 218, 200, 132, 204, 30, 40, 201, 111, 46, 82, 217, 80, 46, 40],
    [40, 207, 84, 80, 238, 104, 141, 53, 17, 89, 167, 177, 191, 198, 160, 55, 6, 125, 165, 221, 213, 29, 239, 133, 111, 33, 36, 195, 34, 186, 38, 150],
    [167, 191, 51, 75, 236, 111, 23, 2, 22, 113, 3, 59, 36, 59, 134, 137, 117, 114, 18, 73, 108, 213, 37, 186, 152, 115, 173, 221, 232, 123, 12, 86],
    [44, 102, 66, 211, 68, 253, 57, 218, 77, 25, 218, 37, 104, 210, 92, 123, 113, 211, 246, 60, 158, 184, 86, 149, 226, 206, 157, 192, 24, 105, 219, 142],
    [208, 81, 56, 111, 96, 138, 190, 108, 246, 119, 213, 203, 223, 59, 145, 227, 68, 28, 206, 104, 82, 56, 154, 210, 113, 97, 121, 72, 126, 10, 141, 137],
    [185, 209, 145, 129, 213, 127, 144, 56, 117, 207, 92, 131, 153, 37, 252, 234, 88, 59, 233, 240, 17, 202, 81, 83, 26, 71, 237, 112, 246, 85, 149, 75],
    [98, 206, 186, 29, 118, 18, 81, 229, 128, 107, 137, 70, 215, 54, 215, 149, 105, 101, 93, 52, 121, 220, 107, 12, 205, 168, 208, 43, 139, 199, 196, 78],
    [220, 194, 139, 117, 88, 23, 145, 161, 4, 63, 93, 213, 100, 18, 191, 5, 2, 52, 205, 124, 223, 60, 159, 255, 252, 249, 113, 18, 46, 4, 60, 118],
    [214, 221, 166, 118, 6, 173, 149, 208, 35, 130, 232, 5, 7, 127, 5, 158, 69, 30, 141, 31, 177, 125, 129, 198, 131, 161, 19, 162, 165, 59, 37, 195],
    [67, 115, 54, 126, 109, 212, 176, 89, 14, 20, 45, 187, 255, 86, 46, 63, 224, 36, 175, 180, 132, 91, 7, 19, 139, 93, 240, 130, 191, 9, 226, 49],
    [206, 151, 131, 65, 16, 81, 134, 92, 185, 138, 47, 80, 73, 28, 220, 40, 230, 2, 216, 56, 247, 25, 255, 247, 45, 60, 19, 202, 131, 185, 156, 65],
    [25, 80, 168, 85, 50, 109, 228, 106, 62, 161, 172, 0, 101, 213, 224, 223, 98, 58, 65, 2, 150, 25, 182, 60, 239, 78, 211, 56, 171, 159, 128, 253],
    [90, 39, 99, 231, 104, 82, 110, 187, 151, 214, 132, 125, 102, 37, 181, 71, 139, 212, 29, 211, 166, 143, 249, 17, 154, 29, 125, 154, 87, 112, 217, 132],
    [248, 0, 219, 163, 128, 133, 137, 189, 177, 194, 129, 67, 218, 237, 221, 61, 81, 186, 234, 91, 202, 246, 161, 11, 9, 231, 119, 108, 110, 200, 175, 19],
    [197, 230, 42, 147, 190, 94, 9, 239, 189, 132, 72, 12, 112, 66, 116, 165, 87, 182, 14, 204, 190, 230, 178, 162, 70, 171, 180, 85, 217, 97, 219, 102],
    [99, 204, 8, 114, 58, 13, 222, 55, 176, 242, 114, 118, 44, 135, 117, 184, 154, 146, 96, 21, 161, 56, 7, 82, 92, 76, 154, 17, 170, 151, 57, 78],
    [253, 80, 163, 195, 195, 146, 190, 178, 126, 76, 62, 215, 5, 180, 228, 36, 180, 155, 119, 119, 96, 59, 85, 156, 141, 157, 205, 102, 7, 100, 93, 66],
    [214, 200, 166, 92, 142, 83, 255, 9, 241, 17, 214, 175, 119, 123, 46, 212, 1, 170, 127, 93, 211, 51, 238, 43, 0, 38, 145, 159, 168, 79, 100, 158],
    [49, 179, 111, 128, 17, 23, 255, 15, 68, 153, 153, 142, 229, 174, 113, 67, 36, 129, 56, 23, 212, 118, 18, 17, 212, 207, 157, 59, 137, 111, 164, 213],
    [122, 185, 6, 146, 14, 31, 251, 70, 144, 2, 158, 191, 66, 200, 143, 193, 2, 155, 51, 73, 146, 35, 246, 128, 230, 157, 136, 245, 166, 255, 119, 251],
    [251, 177, 7, 27, 161, 210, 203, 200, 78, 240, 7, 28, 4, 179, 171, 63, 93, 200, 111, 148, 97, 76, 130, 149, 92, 175, 73, 26, 193, 8, 35, 97],
    [87, 20, 102, 245, 21, 148, 182, 157, 248, 90, 91, 129, 202, 20, 204, 195, 170, 41, 44, 242, 152, 134, 237, 105, 112, 95, 216, 179, 226, 195, 223, 142],
    [160, 9, 84, 206, 47, 84, 102, 29, 2, 199, 145, 178, 167, 191, 20, 115, 118, 165, 123, 175, 39, 8, 37, 152, 73, 12, 177, 7, 72, 164, 7, 3],
    [199, 101, 45, 91, 185, 254, 127, 0, 191, 48, 76, 32, 67, 213, 181, 238, 61, 206, 90, 29, 40, 195, 102, 17, 67, 67, 150, 154, 24, 159, 157, 200],
    [40, 216, 158, 32, 174, 251, 150, 154, 102, 25, 228, 195, 116, 56, 111, 145, 119, 157, 176, 238, 62, 191, 78, 98, 91, 202, 20, 105, 214, 160, 63, 70],
    [248, 10, 35, 72, 7, 147, 166, 168, 144, 102, 192, 234, 70, 229, 146, 118, 138, 30, 2, 27, 156, 49, 192, 44, 89, 182, 7, 64, 12, 250, 69, 225],
    [187, 51, 66, 246, 87, 198, 58, 47, 245, 245, 54, 101, 111, 10, 150, 236, 171, 218, 52, 229, 227, 205, 12, 4, 169, 247, 193, 207, 77, 210, 163, 226],
    [67, 21, 81, 105, 142, 146, 108, 174, 198, 67, 47, 35, 70, 180, 47, 123, 163, 60, 51, 209, 245, 84, 154, 118, 199, 85, 241, 161, 24, 76, 28, 44],
    [123, 92, 89, 183, 156, 40, 140, 239, 192, 118, 91, 23, 91, 10, 224, 219, 243, 37, 101, 21, 76, 33, 187, 49, 63, 76, 243, 232, 123, 123, 11, 181],
    [143, 117, 85, 255, 63, 148, 49, 254, 97, 162, 65, 15, 215, 22, 178, 57, 135, 77, 20, 87, 223, 4, 23, 56, 58, 151, 110, 168, 109, 209, 197, 156],
    [227, 63, 154, 1, 223, 177, 232, 32, 121, 236, 249, 236, 212, 202, 172, 143, 0, 23, 239, 214, 220, 173, 225, 128, 2, 13, 142, 36, 129, 214, 160, 195],
    [241, 130, 77, 83, 223, 84, 39, 87, 192, 161, 179, 55, 104, 36, 83, 206, 87, 109, 163, 79, 155, 9, 204, 171, 213, 94, 21, 63, 87, 39, 213, 214],
    [154, 217, 212, 59, 197, 28, 204, 28, 93, 97, 164, 79, 35, 95, 209, 188, 156, 31, 15, 64, 126, 49, 189, 42, 124, 138, 25, 162, 98, 167, 243, 70],
    [213, 104, 142, 67, 35, 63, 192, 239, 92, 93, 31, 202, 120, 195, 32, 183, 1, 247, 160, 85, 64, 178, 35, 204, 156, 174, 151, 24, 224, 235, 214, 58],
    [223, 100, 75, 72, 198, 79, 121, 249, 42, 203, 181, 63, 5, 85, 15, 26, 142, 250, 41, 91, 207, 28, 68, 95, 64, 196, 160, 186, 92, 96, 190, 219],
    [73, 191, 185, 140, 126, 85, 141, 30, 119, 169, 176, 92, 221, 251, 180, 166, 255, 73, 118, 126, 85, 15, 124, 20, 45, 80, 239, 4, 75, 166, 251, 129],
    [152, 53, 250, 107, 244, 226, 10, 155, 158, 168, 18, 80, 99, 2, 233, 137, 130, 114, 26, 108, 248, 210, 202, 230, 122, 245, 113, 41, 191, 33, 174, 144],
    [235, 34, 180, 140, 99, 108, 213, 211, 22, 51, 181, 143, 95, 202, 242, 78, 139, 55, 80, 197, 182, 241, 207, 7, 227, 6, 20, 102, 175, 230, 175, 144],
    [155, 2, 230, 129, 225, 140, 208, 168, 94, 112, 41, 244, 142, 170, 225, 192, 42, 234, 139, 60, 186, 63, 93, 142, 100, 52, 34, 131, 140, 51, 102, 242],
    [165, 246, 185, 117, 130, 152, 35, 119, 93, 188, 221, 3, 136, 155, 77, 179, 238, 114, 43, 4, 223, 100, 53, 59, 74, 3, 197, 32, 125, 25, 59, 232],
    [191, 157, 184, 229, 142, 138, 199, 52, 179, 49, 60, 227, 154, 205, 39, 161, 187, 152, 196, 53, 178, 179, 145, 44, 170, 149, 34, 127, 177, 80, 84, 246],
    [26, 66, 67, 25, 250, 173, 23, 109, 154, 70, 152, 44, 164, 42, 138, 19, 137, 174, 171, 177, 140, 187, 85, 155, 249, 128, 28, 119, 157, 232, 193, 219],
    [76, 239, 219, 161, 186, 141, 57, 117, 243, 44, 186, 201, 242, 39, 199, 230, 182, 230, 99, 67, 158, 121, 133, 97, 107, 187, 92, 97, 130, 77, 187, 12],
    [44, 220, 118, 247, 139, 199, 164, 87, 45, 69, 48, 174, 250, 223, 129, 13, 183, 192, 185, 80, 165, 242, 197, 194, 15, 248, 45, 83, 41, 66, 109, 164],
    [156, 92, 178, 74, 126, 24, 80, 156, 40, 155, 180, 52, 37, 231, 75, 93, 127, 99, 95, 195, 31, 96, 64, 164, 10, 223, 181, 110, 43, 69, 13, 240],
    [184, 15, 135, 249, 109, 127, 90, 154, 12, 189, 20, 162, 224, 27, 135, 110, 239, 73, 106, 98, 47, 150, 200, 179, 211, 166, 249, 238, 232, 158, 128, 167],
    [135, 251, 47, 109, 21, 11, 88, 24, 152, 106, 143, 163, 86, 46, 167, 87, 215, 185, 171, 92, 168, 227, 42, 165, 223, 5, 138, 72, 95, 11, 150, 49],
    [64, 89, 23, 249, 144, 95, 166, 164, 54, 66, 155, 17, 87, 40, 234, 176, 97, 198, 36, 242, 111, 151, 102, 126, 146, 139, 59, 140, 169, 180, 118, 152],
    [63, 2, 30, 142, 220, 124, 235, 102, 33, 131, 187, 152, 17, 7, 23, 205, 117, 200, 205, 184, 10, 218, 191, 26, 100, 32, 167, 138, 152, 218, 63, 78],
    [25, 233, 67, 254, 144, 12, 82, 73, 93, 65, 202, 116, 235, 85, 22, 72, 2, 106, 76, 68, 248, 32, 154, 187, 238, 113, 235, 115, 206, 206, 65, 234],
    [65, 104, 53, 25, 162, 136, 38, 65, 220, 68, 77, 102, 76, 251, 189, 201, 60, 94, 8, 69, 173, 80, 156, 107, 246, 151, 11, 67, 114, 210, 186, 205],
    [147, 170, 163, 195, 174, 188, 211, 236, 168, 116, 118, 22, 159, 214, 194, 217, 196, 176, 253, 4, 146, 51, 123, 240, 1, 110, 158, 253, 75, 29, 81, 114],
    [5, 16, 72, 168, 138, 146, 169, 55, 147, 1, 201, 26, 226, 233, 144, 169, 29, 247, 9, 193, 135, 49, 6, 1, 10, 111, 156, 21, 191, 143, 34, 133],
    [52, 32, 92, 199, 73, 50, 233, 84, 179, 199, 224, 202, 186, 223, 229, 157, 71, 84, 31, 21, 130, 37, 57, 214, 198, 212, 209, 134, 184, 240, 163, 107],
    [164, 121, 151, 154, 243, 102, 229, 128, 247, 178, 254, 137, 79, 88, 63, 196, 105, 247, 135, 75, 70, 189, 175, 209, 153, 44, 126, 233, 10, 150, 76, 83],
    [68, 77, 47, 151, 18, 14, 101, 114, 72, 242, 32, 64, 118, 6, 3, 119, 86, 180, 228, 236, 234, 251, 154, 165, 55, 2, 122, 81, 2, 173, 214, 25],
    [254, 225, 168, 72, 203, 103, 99, 195, 8, 138, 14, 82, 53, 65, 180, 106, 193, 113, 175, 38, 119, 176, 98, 23, 138, 145, 22, 196, 97, 43, 53, 47],
    [211, 221, 123, 213, 150, 215, 178, 216, 187, 151, 85, 195, 83, 105, 212, 211, 245, 89, 110, 178, 190, 238, 69, 161, 65, 200, 145, 157, 125, 29, 207, 37],
    [121, 219, 254, 96, 50, 143, 25, 40, 21, 153, 144, 87, 247, 88, 58, 108, 101, 223, 59, 176, 11, 172, 111, 29, 97, 196, 234, 88, 234, 230, 106, 61],
    [207, 93, 211, 228, 66, 70, 43, 13, 109, 42, 61, 40, 33, 121, 72, 154, 24, 251, 252, 60, 145, 161, 127, 251, 215, 201, 13, 105, 85, 3, 160, 26],
    [13, 65, 194, 77, 103, 16, 59, 119, 110, 24, 41, 224, 165, 43, 172, 89, 213, 225, 37, 164, 231, 183, 106, 79, 134, 241, 111, 4, 215, 27, 161, 124],
    [157, 191, 4, 219, 235, 60, 145, 109, 68, 124, 99, 232, 176, 158, 97, 45, 182, 94, 71, 207, 109, 179, 16, 240, 225, 184, 158, 157, 210, 212, 108, 31],
    [241, 123, 58, 183, 224, 149, 111, 5, 251, 241, 110, 42, 193, 245, 161, 149, 189, 52, 149, 173, 33, 47, 187, 50, 173, 229, 191, 215, 96, 68, 169, 121],
    [48, 192, 23, 88, 160, 18, 91, 19, 114, 176, 50, 43, 247, 30, 166, 46, 103, 215, 246, 26, 159, 144, 41, 4, 136, 72, 253, 101, 246, 78, 167, 33],
    [172, 31, 254, 174, 142, 203, 227, 65, 96, 212, 30, 114, 42, 26, 27, 32, 98, 101, 83, 114, 140, 253, 108, 16, 217, 84, 11, 94, 190, 63, 135, 5],
    [6, 233, 30, 216, 64, 11, 173, 60, 60, 85, 225, 197, 191, 153, 19, 194, 232, 6, 215, 184, 224, 19, 229, 28, 21, 18, 74, 234, 34, 23, 152, 207],
    [172, 8, 243, 150, 140, 117, 71, 63, 129, 98, 163, 91, 176, 222, 60, 89, 64, 202, 16, 126, 245, 191, 133, 185, 200, 220, 131, 115, 229, 76, 237, 165],
    [9, 251, 226, 23, 130, 13, 15, 10, 59, 119, 234, 205, 239, 170, 138, 46, 220, 81, 35, 211, 98, 110, 214, 162, 48, 218, 15, 53, 33, 60, 91, 229],
    [196, 126, 204, 33, 114, 4, 105, 251, 49, 91, 16, 79, 97, 213, 223, 60, 214, 233, 3, 91, 70, 39, 244, 47, 255, 50, 22, 149, 181, 239, 133, 50],
    [159, 50, 17, 243, 166, 244, 8, 32, 206, 6, 111, 42, 158, 87, 240, 185, 110, 85, 113, 136, 181, 118, 73, 252, 167, 68, 72, 219, 89, 247, 218, 101],
    [162, 218, 156, 193, 247, 130, 51, 226, 162, 220, 68, 34, 127, 115, 199, 0, 217, 17, 4, 29, 213, 224, 128, 243, 23, 19, 27, 134, 213, 185, 50, 183],
    [243, 121, 154, 35, 130, 125, 187, 137, 143, 80, 144, 154, 230, 182, 43, 33, 201, 113, 190, 196, 203, 143, 50, 99, 31, 81, 75, 60, 165, 23, 87, 134],
    [233, 204, 91, 133, 116, 156, 182, 170, 155, 38, 117, 90, 207, 217, 201, 63, 204, 84, 7, 79, 240, 166, 15, 168, 59, 197, 174, 191, 134, 45, 115, 177],
    [192, 227, 18, 41, 50, 20, 105, 186, 1, 6, 163, 222, 117, 111, 28, 120, 42, 96, 210, 37, 136, 37, 250, 55, 237, 99, 217, 244, 163, 52, 163, 12],
    [160, 227, 79, 66, 67, 37, 47, 51, 191, 134, 64, 31, 48, 249, 202, 12, 80, 232, 238, 219, 201, 26, 64, 58, 80, 188, 162, 240, 65, 143, 201, 199],
    [19, 152, 227, 66, 32, 21, 88, 236, 200, 83, 255, 154, 135, 61, 86, 219, 60, 91, 149, 172, 213, 243, 235, 51, 8, 168, 54, 17, 135, 123, 53, 92],
    [157, 199, 135, 249, 240, 212, 108, 23, 132, 116, 172, 195, 200, 187, 145, 251, 17, 207, 142, 253, 194, 163, 159, 163, 2, 95, 143, 39, 2, 137, 69, 236],
    [245, 165, 190, 15, 32, 149, 175, 69, 142, 91, 52, 21, 168, 165, 19, 88, 119, 155, 240, 232, 61, 48, 246, 100, 156, 228, 62, 143, 224, 40, 92, 26],
    [118, 27, 204, 247, 167, 2, 109, 110, 129, 162, 217, 240, 2, 59, 146, 35, 122, 211, 21, 225, 214, 250, 106, 128, 20, 183, 16, 6, 62, 75, 209, 186],
    [173, 27, 94, 211, 28, 159, 96, 63, 79, 210, 214, 96, 119, 158, 59, 45, 207, 173, 35, 186, 97, 220, 13, 158, 170, 167, 106, 20, 0, 164, 168, 84],
    [129, 1, 228, 161, 246, 229, 176, 176, 18, 105, 26, 210, 233, 170, 193, 81, 31, 105, 191, 31, 188, 78, 103, 39, 79, 150, 109, 220, 252, 162, 80, 40],
    [54, 77, 29, 26, 181, 122, 38, 71, 115, 196, 156, 133, 59, 44, 252, 254, 205, 14, 131, 157, 4, 3, 117, 38, 216, 125, 233, 132, 104, 127, 106, 55],
    [56, 105, 131, 119, 153, 177, 102, 73, 24, 140, 179, 21, 171, 48, 185, 107, 14, 91, 96, 110, 132, 161, 163, 177, 13, 62, 96, 198, 226, 80, 213, 58],
    [58, 126, 99, 78, 247, 120, 109, 61, 80, 125, 228, 188, 213, 30, 140, 96, 28, 83, 35, 232, 136, 75, 116, 47, 121, 45, 205, 197, 151, 255, 95, 116],
    [169, 216, 234, 135, 201, 35, 83, 215, 68, 91, 247, 255, 133, 81, 25, 252, 107, 97, 65, 82, 249, 163, 125, 113, 52, 180, 100, 18, 159, 179, 134, 244],
    [23, 67, 14, 148, 191, 186, 246, 43, 40, 118, 222, 241, 68, 172, 158, 11, 139, 7, 2, 16, 23, 20, 152, 179, 250, 163, 224, 129, 29, 155, 157, 74],
    [112, 97, 34, 149, 233, 15, 172, 225, 212, 249, 132, 37, 211, 167, 35, 246, 133, 184, 3, 201, 156, 199, 37, 7, 80, 132, 251, 176, 82, 173, 176, 5],
    [229, 35, 178, 62, 208, 11, 238, 69, 1, 89, 135, 158, 12, 198, 41, 221, 200, 18, 240, 162, 234, 11, 116, 255, 114, 169, 246, 134, 0, 4, 135, 32],
    [86, 206, 19, 238, 192, 222, 255, 212, 249, 73, 93, 145, 47, 158, 40, 33, 147, 153, 122, 110, 54, 137, 67, 39, 115, 194, 87, 89, 230, 221, 141, 22],
    [31, 115, 131, 145, 79, 13, 144, 139, 117, 186, 19, 143, 48, 164, 26, 49, 20, 7, 6, 53, 18, 58, 46, 81, 85, 56, 238, 226, 82, 116, 248, 1],
    [189, 56, 127, 94, 38, 248, 226, 146, 96, 171, 187, 89, 179, 182, 249, 104, 22, 59, 39, 204, 20, 216, 92, 125, 37, 45, 75, 86, 24, 171, 125, 163],
    [205, 103, 64, 164, 42, 18, 188, 99, 187, 94, 169, 226, 104, 87, 193, 167, 167, 98, 247, 145, 35, 162, 104, 14, 111, 43, 65, 184, 82, 45, 234, 11],
    [155, 173, 73, 48, 118, 161, 92, 61, 4, 203, 46, 31, 65, 96, 126, 240, 244, 114, 112, 248, 167, 158, 191, 22, 32, 187, 185, 211, 227, 30, 25, 30],
    [5, 178, 95, 244, 143, 119, 218, 245, 148, 232, 0, 135, 170, 86, 233, 202, 154, 105, 73, 216, 58, 71, 51, 161, 188, 140, 53, 242, 60, 24, 81, 19],
    [202, 166, 6, 141, 65, 242, 209, 252, 64, 36, 170, 235, 66, 76, 143, 53, 193, 253, 167, 143, 124, 183, 179, 121, 58, 102, 189, 64, 67, 152, 36, 18],
    [35, 132, 9, 86, 232, 226, 239, 115, 104, 67, 146, 186, 20, 32, 37, 29, 57, 28, 225, 190, 73, 163, 87, 1, 234, 117, 10, 152, 55, 15, 100, 195],
    [251, 121, 23, 228, 227, 247, 127, 67, 111, 125, 164, 78, 110, 120, 153, 240, 185, 26, 215, 180, 59, 249, 0, 101, 62, 178, 41, 173, 116, 89, 107, 37],
    [6, 32, 118, 209, 121, 251, 135, 87, 90, 214, 217, 93, 29, 155, 33, 112, 254, 167, 123, 22, 109, 67, 52, 82, 151, 38, 216, 220, 137, 255, 69, 48],
    [135, 154, 125, 240, 6, 60, 197, 120, 171, 57, 141, 84, 194, 237, 113, 33, 190, 169, 125, 243, 47, 159, 235, 93, 46, 196, 128, 227, 10, 215, 110, 82],
    [94, 48, 98, 199, 154, 184, 39, 64, 30, 159, 137, 247, 2, 149, 161, 2, 138, 49, 216, 144, 90, 60, 17, 136, 193, 62, 10, 179, 116, 177, 13, 194],
    [186, 248, 65, 118, 157, 222, 79, 25, 246, 225, 232, 185, 157, 71, 236, 41, 240, 68, 5, 156, 200, 195, 33, 18, 115, 54, 107, 101, 191, 123, 129, 9],
    [104, 235, 27, 245, 83, 32, 112, 35, 165, 183, 252, 9, 109, 10, 140, 137, 189, 246, 117, 226, 60, 75, 145, 168, 157, 69, 250, 165, 2, 156, 123, 153],
    [113, 164, 23, 188, 177, 31, 172, 105, 73, 126, 162, 50, 194, 230, 41, 15, 136, 199, 148, 191, 119, 82, 200, 70, 127, 152, 92, 212, 221, 17, 194, 57],
    [124, 255, 77, 24, 198, 178, 221, 216, 168, 194, 127, 86, 158, 136, 112, 34, 119, 11, 100, 66, 19, 3, 28, 240, 41, 204, 120, 104, 83, 197, 86, 255],
    [51, 242, 100, 208, 60, 60, 17, 232, 107, 58, 67, 154, 178, 17, 26, 139, 224, 32, 91, 178, 246, 91, 200, 126, 41, 172, 94, 68, 149, 182, 216, 38],
    [48, 50, 157, 69, 83, 245, 235, 234, 126, 176, 235, 25, 68, 168, 131, 216, 143, 221, 206, 13, 49, 199, 133, 164, 238, 52, 199, 85, 187, 40, 227, 220],
    [39, 221, 197, 142, 204, 88, 253, 134, 147, 55, 72, 26, 247, 115, 2, 213, 77, 213, 186, 145, 132, 33, 68, 248, 125, 235, 131, 36, 9, 6, 157, 11],
    [96, 149, 32, 17, 204, 124, 178, 93, 249, 137, 97, 253, 129, 172, 53, 192, 192, 244, 123, 27, 206, 110, 105, 155, 249, 3, 158, 209, 26, 170, 180, 121],
    [89, 166, 232, 110, 146, 129, 238, 224, 160, 178, 73, 33, 167, 142, 21, 190, 227, 49, 25, 117, 137, 20, 229, 177, 131, 247, 85, 110, 86, 215, 22, 82],
    [76, 4, 172, 98, 122, 20, 45, 106, 247, 113, 156, 173, 109, 112, 246, 223, 69, 205, 223, 76, 205, 112, 148, 81, 115, 109, 246, 76, 228, 187, 209, 47],
    [229, 163, 84, 201, 62, 23, 146, 19, 213, 154, 155, 57, 73, 81, 230, 62, 70, 89, 243, 241, 110, 165, 233, 188, 201, 152, 35, 250, 237, 155, 23, 239],
    [128, 41, 28, 226, 66, 224, 9, 118, 80, 40, 247, 48, 84, 186, 227, 137, 109, 90, 23, 78, 194, 207, 181, 39, 121, 249, 13, 11, 209, 100, 30, 127],
    [86, 130, 214, 179, 104, 51, 121, 243, 133, 0, 167, 95, 174, 80, 242, 97, 160, 153, 119, 27, 84, 35, 232, 209, 187, 15, 110, 114, 29, 8, 1, 129],
    [211, 12, 138, 63, 174, 56, 177, 245, 18, 253, 21, 174, 123, 8, 117, 79, 148, 48, 194, 76, 120, 12, 28, 78, 151, 7, 45, 5, 145, 227, 181, 146],
    [156, 41, 143, 43, 0, 66, 102, 211, 18, 144, 185, 14, 149, 228, 96, 26, 216, 250, 214, 226, 159, 30, 79, 69, 78, 241, 51, 198, 111, 238, 32, 84],
    [143, 59, 165, 192, 52, 79, 103, 47, 63, 168, 183, 18, 167, 88, 195, 43, 168, 236, 12, 107, 238, 42, 220, 119, 247, 45, 204, 183, 104, 214, 16, 82],
    [101, 72, 56, 144, 182, 24, 193, 1, 181, 203, 51, 187, 56, 119, 123, 124, 155, 58, 100, 115, 66, 247, 208, 107, 190, 121, 136, 248, 134, 128, 88, 16],
    [98, 24, 23, 152, 68, 93, 61, 182, 193, 174, 118, 100, 182, 79, 49, 241, 186, 31, 66, 28, 102, 141, 208, 45, 75, 245, 108, 138, 78, 238, 134, 102],
    [249, 174, 58, 221, 6, 118, 151, 215, 188, 124, 208, 246, 141, 205, 25, 253, 91, 198, 189, 71, 88, 24, 220, 226, 248, 0, 209, 245, 91, 228, 102, 52],
    [241, 80, 44, 1, 177, 249, 206, 230, 243, 163, 142, 136, 184, 214, 39, 197, 188, 40, 187, 154, 135, 245, 42, 84, 105, 226, 192, 191, 73, 198, 227, 89],
    [169, 79, 54, 118, 105, 109, 42, 215, 212, 153, 27, 52, 164, 121, 198, 6, 208, 207, 20, 164, 246, 126, 200, 225, 94, 163, 98, 68, 201, 171, 39, 200],
    [99, 115, 16, 177, 169, 100, 12, 177, 155, 116, 99, 60, 85, 55, 249, 167, 165, 128, 9, 199, 49, 174, 30, 220, 22, 176, 108, 149, 149, 82, 160, 175],
    [223, 98, 65, 172, 47, 142, 83, 45, 224, 111, 20, 54, 7, 204, 175, 255, 60, 241, 16, 174, 93, 232, 138, 47, 100, 189, 129, 166, 212, 95, 216, 173],
    [74, 153, 239, 243, 68, 95, 204, 72, 48, 190, 83, 111, 205, 49, 61, 155, 203, 56, 180, 216, 121, 161, 105, 116, 50, 154, 159, 2, 87, 211, 155, 208],
    [95, 245, 36, 52, 193, 67, 137, 247, 247, 23, 127, 241, 155, 237, 136, 226, 64, 5, 244, 25, 158, 174, 166, 101, 179, 45, 129, 203, 136, 91, 234, 228],
    [59, 182, 91, 109, 32, 11, 79, 42, 2, 129, 182, 91, 234, 119, 25, 58, 162, 215, 20, 38, 205, 126, 243, 123, 80, 187, 100, 132, 14, 180, 156, 30],
    [160, 90, 196, 174, 155, 125, 175, 158, 134, 185, 240, 236, 169, 66, 154, 207, 254, 21, 125, 167, 54, 212, 216, 234, 34, 0, 132, 131, 150, 145, 114, 112],
    [255, 247, 96, 163, 31, 121, 115, 188, 177, 90, 212, 49, 18, 112, 109, 116, 150, 158, 107, 107, 171, 215, 72, 70, 227, 249, 190, 228, 102, 5, 102, 47],
    [135, 56, 44, 28, 146, 0, 128, 110, 20, 76, 178, 240, 224, 231, 157, 213, 141, 128, 102, 242, 203, 70, 17, 80, 108, 97, 103, 39, 176, 229, 229, 239],
    [50, 238, 0, 157, 35, 244, 137, 74, 181, 59, 225, 47, 222, 61, 250, 90, 238, 106, 159, 68, 68, 82, 165, 190, 104, 40, 169, 221, 118, 39, 46, 252],
    [70, 242, 77, 61, 86, 24, 17, 230, 168, 48, 32, 101, 165, 67, 164, 161, 59, 139, 132, 165, 48, 78, 41, 203, 86, 41, 0, 239, 130, 98, 213, 187],
    [112, 83, 110, 252, 72, 171, 11, 159, 106, 45, 77, 190, 2, 141, 197, 146, 139, 167, 250, 43, 243, 146, 186, 204, 128, 100, 251, 174, 200, 66, 149, 171],
    [115, 159, 7, 23, 226, 75, 118, 3, 71, 219, 126, 180, 123, 212, 138, 42, 148, 12, 92, 122, 222, 14, 125, 191, 174, 162, 126, 92, 182, 52, 93, 143],
    [6, 204, 16, 1, 206, 126, 123, 75, 188, 160, 176, 53, 84, 125, 4, 243, 29, 42, 121, 1, 210, 139, 236, 88, 40, 222, 255, 18, 86, 96, 103, 207],
    [229, 222, 117, 214, 230, 47, 47, 196, 211, 183, 33, 173, 196, 77, 175, 182, 47, 25, 114, 251, 49, 80, 114, 146, 27, 125, 109, 132, 73, 4, 31, 6],
    [247, 28, 45, 212, 243, 113, 80, 244, 32, 184, 61, 76, 115, 58, 162, 235, 102, 29, 81, 14, 125, 41, 86, 33, 99, 89, 137, 217, 93, 3, 137, 156],
    [171, 213, 229, 75, 227, 245, 157, 142, 228, 148, 59, 35, 128, 222, 241, 127, 84, 110, 96, 76, 197, 29, 168, 185, 201, 63, 89, 31, 32, 94, 117, 219],
    [21, 40, 71, 132, 97, 19, 83, 182, 239, 230, 54, 115, 220, 238, 214, 38, 51, 232, 78, 81, 207, 205, 101, 176, 192, 188, 255, 151, 148, 217, 192, 159],
    [99, 156, 113, 172, 94, 251, 32, 60, 213, 200, 216, 94, 56, 146, 96, 91, 53, 31, 141, 15, 36, 202, 208, 100, 241, 126, 7, 255, 198, 92, 221, 1],
    [174, 199, 233, 198, 33, 34, 193, 186, 151, 200, 59, 38, 175, 38, 39, 71, 2, 90, 217, 197, 184, 27, 253, 140, 159, 118, 222, 172, 235, 9, 113, 111],
    [117, 80, 94, 65, 6, 143, 163, 4, 11, 59, 48, 243, 4, 0, 35, 246, 94, 152, 81, 62, 223, 137, 84, 211, 125, 174, 30, 222, 236, 19, 58, 5],
    [221, 60, 230, 244, 86, 43, 140, 96, 211, 192, 72, 144, 160, 157, 97, 185, 71, 244, 157, 117, 72, 68, 190, 16, 68, 35, 222, 170, 108, 225, 176, 205],
    [64, 241, 176, 191, 106, 131, 207, 148, 243, 177, 16, 4, 141, 100, 63, 254, 139, 202, 122, 255, 56, 221, 233, 144, 67, 249, 148, 90, 23, 47, 44, 240],
    [59, 134, 205, 20, 29, 119, 95, 79, 36, 80, 71, 130, 3, 159, 176, 124, 240, 173, 220, 146, 208, 16, 216, 28, 143, 135, 51, 56, 144, 24, 47, 166],
    [217, 218, 3, 41, 100, 163, 196, 78, 75, 104, 91, 173, 107, 119, 124, 70, 18, 189, 10, 65, 38, 151, 166, 32, 115, 225, 162, 164, 31, 112, 241, 30],
    [152, 236, 159, 43, 123, 217, 249, 89, 250, 56, 156, 30, 175, 8, 23, 14, 129, 106, 90, 54, 193, 85, 142, 44, 161, 81, 223, 157, 226, 185, 141, 230],
    [219, 237, 216, 85, 121, 8, 194, 12, 127, 204, 185, 128, 13, 7, 235, 148, 53, 45, 239, 171, 239, 97, 191, 242, 202, 202, 123, 13, 234, 59, 57, 228],
    [13, 75, 186, 45, 243, 98, 216, 6, 189, 225, 159, 40, 179, 152, 37, 70, 137, 132, 225, 35, 175, 253, 182, 217, 20, 172, 1, 48, 1, 206, 131, 46],
    [86, 235, 98, 11, 99, 106, 0, 20, 59, 214, 129, 85, 192, 154, 86, 93, 83, 118, 162, 235, 202, 154, 60, 204, 238, 243, 63, 187, 254, 101, 140, 141],
    [59, 243, 241, 253, 93, 37, 187, 134, 146, 104, 70, 13, 235, 13, 10, 95, 108, 141, 149, 201, 21, 163, 93, 116, 99, 5, 184, 152, 218, 116, 165, 21],
    [64, 131, 72, 231, 13, 236, 84, 95, 100, 210, 133, 225, 135, 167, 162, 112, 246, 54, 125, 56, 165, 155, 189, 6, 153, 123, 22, 4, 10, 35, 155, 106],
    [134, 20, 11, 194, 79, 195, 183, 216, 7, 96, 124, 34, 188, 27, 125, 155, 123, 145, 195, 225, 115, 159, 215, 59, 19, 140, 0, 239, 109, 245, 193, 228],
    [173, 98, 224, 199, 251, 140, 198, 108, 41, 245, 154, 63, 234, 253, 14, 107, 64, 185, 77, 162, 136, 51, 144, 32, 61, 158, 126, 71, 97, 162, 111, 71],
    [28, 142, 250, 94, 5, 0, 48, 82, 79, 153, 211, 216, 198, 100, 209, 95, 56, 181, 229, 122, 109, 191, 72, 65, 174, 112, 221, 224, 43, 108, 224, 112],
    [172, 182, 189, 14, 243, 37, 194, 216, 91, 174, 242, 179, 36, 111, 146, 179, 159, 107, 146, 13, 251, 244, 14, 20, 255, 190, 16, 47, 84, 232, 205, 247],
    [161, 96, 102, 48, 136, 138, 213, 169, 50, 193, 79, 190, 56, 130, 159, 213, 26, 71, 252, 189, 201, 202, 106, 34, 204, 67, 132, 14, 18, 128, 3, 87],
    [225, 10, 133, 207, 118, 6, 114, 165, 8, 134, 115, 182, 210, 44, 71, 109, 100, 233, 250, 200, 154, 5, 7, 23, 160, 184, 123, 210, 83, 134, 154, 196],
    [171, 111, 174, 213, 198, 123, 119, 241, 70, 57, 180, 39, 247, 77, 103, 207, 23, 217, 71, 187, 58, 138, 89, 35, 137, 164, 166, 199, 127, 24, 22, 255],
    [190, 20, 119, 170, 154, 55, 208, 146, 22, 61, 209, 63, 172, 11, 223, 21, 50, 100, 36, 248, 201, 101, 202, 158, 241, 2, 62, 145, 65, 97, 196, 70],
    [91, 250, 67, 128, 77, 83, 240, 62, 155, 62, 109, 173, 160, 148, 236, 143, 99, 84, 152, 100, 181, 153, 192, 115, 186, 180, 172, 39, 205, 225, 15, 98],
    [203, 158, 76, 67, 153, 201, 114, 118, 78, 136, 116, 63, 59, 114, 4, 107, 32, 68, 3, 52, 204, 20, 214, 117, 58, 55, 193, 235, 14, 247, 9, 1],
    [110, 191, 97, 132, 233, 154, 87, 85, 50, 2, 82, 63, 227, 185, 46, 103, 253, 248, 210, 222, 102, 198, 221, 242, 153, 126, 169, 1, 229, 218, 12, 222],
    [208, 175, 50, 73, 227, 167, 11, 17, 43, 182, 52, 189, 242, 127, 15, 41, 158, 160, 194, 57, 53, 105, 167, 221, 71, 22, 4, 228, 86, 108, 194, 89],
    [160, 95, 97, 66, 36, 230, 147, 120, 22, 120, 126, 239, 232, 213, 242, 223, 61, 108, 38, 130, 111, 103, 171, 66, 174, 186, 153, 146, 85, 142, 65, 105],
    [193, 155, 108, 21, 48, 169, 69, 156, 243, 166, 26, 39, 105, 11, 151, 220, 99, 113, 243, 79, 125, 39, 194, 161, 158, 155, 162, 74, 143, 2, 241, 18],
    [8, 117, 102, 20, 60, 75, 125, 59, 58, 150, 218, 144, 193, 69, 242, 163, 8, 69, 78, 37, 60, 245, 22, 239, 79, 188, 16, 121, 172, 172, 92, 206],
    [166, 49, 11, 145, 159, 250, 239, 124, 200, 149, 90, 82, 58, 155, 152, 241, 217, 17, 225, 37, 229, 120, 43, 146, 250, 204, 134, 157, 129, 216, 83, 102],
    [30, 212, 215, 184, 120, 29, 105, 25, 127, 25, 216, 248, 217, 16, 127, 93, 121, 202, 122, 50, 121, 147, 192, 134, 85, 213, 16, 248, 139, 139, 149, 215],
    [18, 43, 58, 215, 226, 239, 19, 117, 125, 150, 6, 222, 124, 22, 253, 131, 170, 210, 236, 11, 133, 63, 147, 248, 195, 120, 111, 216, 59, 119, 206, 26],
    [61, 9, 249, 77, 70, 4, 204, 38, 145, 180, 255, 125, 25, 117, 165, 108, 128, 62, 72, 68, 199, 97, 0, 90, 40, 23, 54, 90, 37, 74, 17, 110],
    [217, 103, 204, 85, 5, 157, 0, 130, 182, 178, 71, 210, 167, 215, 251, 121, 183, 221, 237, 169, 123, 229, 146, 125, 244, 12, 249, 100, 44, 238, 198, 211],
    [33, 38, 252, 55, 44, 116, 186, 175, 9, 243, 248, 163, 81, 216, 56, 158, 14, 225, 126, 253, 106, 12, 137, 48, 165, 190, 27, 93, 227, 39, 124, 65],
    [74, 217, 97, 222, 56, 2, 57, 118, 50, 43, 130, 249, 218, 87, 171, 179, 47, 53, 78, 165, 123, 80, 225, 80, 142, 36, 181, 250, 112, 163, 125, 178],
    [47, 121, 109, 68, 91, 124, 29, 172, 248, 192, 254, 225, 28, 28, 106, 85, 12, 48, 196, 30, 90, 145, 39, 150, 84, 94, 142, 55, 11, 251, 126, 1],
    [175, 23, 195, 253, 48, 154, 33, 139, 243, 100, 45, 59, 251, 121, 107, 53, 123, 114, 151, 221, 23, 166, 221, 121, 122, 9, 37, 244, 170, 137, 74, 98],
    [226, 24, 200, 182, 62, 63, 20, 17, 212, 81, 186, 255, 50, 174, 49, 199, 162, 12, 153, 193, 167, 93, 74, 144, 133, 164, 169, 65, 197, 68, 87, 106],
    [25, 91, 6, 216, 145, 24, 130, 196, 241, 145, 235, 179, 4, 228, 247, 69, 166, 132, 185, 244, 41, 247, 54, 247, 133, 171, 219, 43, 211, 21, 201, 167],
    [160, 96, 5, 100, 78, 47, 178, 140, 34, 144, 42, 172, 7, 119, 216, 62, 3, 154, 105, 56, 28, 56, 153, 160, 118, 233, 32, 232, 140, 222, 181, 120],
    [174, 30, 254, 208, 170, 221, 22, 21, 137, 141, 63, 199, 229, 78, 232, 29, 181, 52, 146, 183, 168, 210, 228, 4, 111, 89, 254, 143, 152, 68, 79, 235],
    [22, 159, 244, 118, 7, 160, 11, 165, 59, 152, 216, 146, 28, 61, 106, 166, 195, 10, 33, 249, 119, 128, 98, 139, 75, 80, 181, 255, 242, 222, 40, 145],
    [94, 82, 182, 38, 224, 68, 115, 84, 47, 41, 249, 211, 23, 154, 32, 219, 144, 38, 114, 121, 5, 165, 32, 90, 209, 118, 100, 101, 21, 59, 223, 225],
    [202, 254, 40, 190, 193, 211, 60, 230, 186, 158, 113, 62, 247, 183, 120, 237, 7, 80, 58, 4, 168, 124, 41, 185, 36, 123, 110, 179, 145, 189, 254, 199],
    [56, 245, 29, 46, 221, 157, 40, 185, 154, 51, 47, 164, 86, 76, 36, 110, 102, 72, 118, 76, 45, 211, 156, 92, 85, 8, 224, 59, 22, 112, 40, 92],
    [227, 74, 32, 43, 214, 11, 242, 14, 194, 211, 87, 22, 22, 146, 81, 237, 153, 210, 194, 204, 87, 223, 13, 200, 93, 203, 2, 79, 240, 183, 151, 200],
    [137, 132, 240, 71, 185, 51, 45, 227, 73, 232, 47, 95, 133, 91, 240, 210, 36, 188, 236, 155, 60, 127, 89, 249, 174, 2, 44, 173, 68, 17, 159, 101],
    [240, 135, 61, 103, 118, 93, 115, 42, 59, 87, 86, 94, 149, 103, 203, 74, 201, 168, 147, 230, 100, 116, 207, 118, 184, 91, 57, 146, 52, 40, 49, 149],
    [253, 37, 210, 77, 123, 80, 156, 24, 143, 225, 178, 242, 123, 39, 29, 248, 77, 69, 137, 149, 56, 120, 252, 13, 216, 196, 200, 142, 214, 69, 213, 6],
    [242, 66, 129, 83, 7, 34, 108, 117, 53, 66, 240, 227, 146, 235, 19, 102, 161, 229, 5, 102, 192, 233, 67, 144, 172, 244, 153, 125, 237, 0, 161, 227],
    [26, 95, 30, 50, 87, 224, 167, 109, 9, 138, 96, 153, 165, 42, 99, 33, 17, 134, 186, 104, 131, 75, 93, 179, 191, 93, 196, 132, 131, 26, 164, 112],
    [69, 239, 132, 198, 225, 135, 6, 32, 187, 228, 212, 172, 63, 119, 227, 129, 116, 231, 183, 113, 193, 27, 124, 94, 112, 247, 98, 22, 238, 216, 230, 186],
    [222, 118, 248, 253, 0, 71, 101, 31, 212, 34, 49, 85, 233, 115, 184, 105, 100, 253, 27, 188, 151, 194, 110, 202, 164, 115, 177, 222, 64, 241, 247, 76],
    [232, 13, 97, 128, 173, 255, 210, 150, 181, 36, 193, 58, 135, 140, 223, 163, 228, 80, 0, 57, 209, 57, 105, 209, 182, 76, 138, 45, 184, 178, 56, 67],
    [40, 66, 83, 172, 118, 92, 230, 94, 175, 92, 32, 65, 250, 158, 90, 3, 179, 221, 242, 116, 54, 136, 214, 71, 163, 239, 207, 119, 153, 129, 69, 211],
    [48, 237, 206, 183, 8, 30, 24, 241, 65, 93, 137, 39, 60, 245, 196, 93, 230, 239, 14, 52, 199, 140, 69, 166, 236, 56, 177, 252, 87, 9, 196, 247],
    [35, 253, 215, 229, 47, 255, 20, 204, 168, 118, 37, 180, 4, 0, 224, 232, 97, 32, 26, 18, 59, 86, 236, 107, 217, 236, 61, 21, 17, 194, 220, 31],
    [52, 37, 19, 4, 238, 115, 192, 76, 63, 125, 176, 226, 129, 87, 156, 22, 190, 189, 240, 239, 151, 185, 104, 139, 37, 33, 14, 87, 28, 198, 196, 15],
    [154, 249, 148, 150, 60, 87, 195, 102, 82, 1, 184, 36, 242, 211, 21, 146, 252, 66, 115, 52, 185, 226, 163, 202, 238, 83, 191, 94, 65, 101, 184, 30],
    [149, 145, 222, 255, 203, 106, 70, 21, 224, 206, 215, 203, 215, 99, 167, 206, 89, 143, 210, 151, 70, 43, 134, 235, 52, 78, 221, 28, 9, 39, 219, 0],
    [202, 156, 70, 53, 56, 197, 128, 147, 71, 111, 58, 192, 167, 176, 208, 252, 145, 178, 159, 196, 31, 67, 225, 89, 189, 59, 231, 58, 72, 238, 245, 212],
    [54, 213, 182, 197, 171, 184, 231, 35, 107, 82, 186, 86, 57, 35, 243, 255, 61, 153, 94, 163, 132, 92, 209, 141, 30, 254, 109, 26, 34, 152, 211, 137],
    [226, 24, 205, 41, 219, 250, 190, 226, 229, 45, 148, 29, 20, 103, 25, 110, 113, 91, 53, 45, 163, 30, 162, 220, 70, 12, 84, 127, 175, 33, 210, 67],
    [232, 57, 5, 157, 61, 71, 136, 142, 248, 153, 7, 50, 202, 81, 239, 47, 46, 48, 87, 65, 162, 163, 67, 135, 121, 215, 18, 205, 168, 54, 227, 252],
    [183, 103, 229, 173, 179, 102, 206, 43, 233, 115, 74, 154, 49, 111, 193, 67, 68, 97, 140, 176, 86, 165, 163, 183, 131, 198, 143, 173, 136, 78, 226, 14],
    [149, 143, 243, 110, 97, 242, 81, 83, 41, 37, 28, 80, 24, 144, 184, 40, 203, 19, 49, 43, 137, 227, 227, 36, 60, 209, 192, 38, 70, 115, 57, 30],
    [252, 109, 38, 131, 215, 30, 120, 160, 171, 86, 149, 214, 103, 118, 75, 156, 238, 133, 6, 204, 245, 252, 104, 212, 35, 182, 31, 241, 79, 146, 11, 44],
    [221, 139, 45, 93, 240, 81, 37, 144, 4, 122, 133, 231, 84, 190, 14, 211, 142, 97, 205, 186, 144, 181, 17, 102, 240, 184, 3, 197, 115, 230, 212, 158],
    [158, 202, 109, 32, 62, 116, 113, 18, 175, 211, 84, 46, 160, 7, 173, 10, 46, 20, 251, 221, 61, 98, 248, 7, 128, 170, 131, 5, 20, 64, 9, 94],
    [183, 21, 61, 123, 7, 79, 229, 50, 143, 207, 253, 59, 147, 17, 196, 214, 43, 160, 198, 144, 35, 143, 45, 196, 123, 76, 212, 162, 186, 189, 211, 171],
    [41, 22, 86, 192, 2, 243, 72, 82, 205, 146, 85, 82, 174, 17, 199, 154, 122, 132, 52, 177, 40, 114, 173, 116, 78, 172, 54, 157, 194, 68, 116, 107],
    [178, 130, 208, 89, 122, 198, 162, 83, 217, 49, 16, 19, 253, 156, 117, 250, 18, 19, 81, 134, 225, 148, 224, 82, 80, 109, 160, 160, 208, 203, 111, 245],
    [134, 14, 171, 4, 142, 151, 114, 38, 203, 243, 201, 242, 13, 146, 206, 73, 209, 236, 86, 106, 232, 205, 77, 138, 129, 83, 211, 178, 57, 45, 214, 85],
    [193, 143, 26, 114, 161, 52, 187, 70, 41, 5, 183, 205, 33, 118, 107, 182, 236, 89, 234, 136, 61, 73, 106, 108, 166, 151, 61, 106, 149, 217, 205, 160],
    [243, 103, 128, 202, 114, 88, 244, 99, 191, 114, 178, 53, 130, 230, 246, 3, 228, 220, 208, 85, 28, 203, 131, 112, 249, 204, 76, 28, 255, 55, 117, 35],
    [216, 36, 211, 187, 136, 45, 106, 56, 235, 136, 69, 20, 81, 141, 35, 5, 35, 145, 177, 217, 139, 168, 114, 230, 151, 22, 203, 175, 204, 243, 203, 246],
    [124, 237, 165, 31, 171, 233, 229, 240, 98, 198, 106, 146, 98, 148, 72, 236, 134, 227, 236, 245, 213, 26, 70, 74, 35, 236, 36, 217, 165, 15, 61, 221],
    [152, 4, 142, 173, 30, 164, 238, 21, 73, 127, 117, 173, 159, 102, 135, 217, 194, 170, 91, 208, 22, 108, 238, 30, 184, 69, 195, 205, 212, 254, 37, 137],
    [91, 166, 100, 116, 156, 106, 205, 16, 5, 159, 118, 28, 222, 17, 204, 121, 28, 222, 197, 128, 208, 131, 204, 177, 30, 225, 7, 124, 209, 74, 182, 29],
    [24, 100, 250, 252, 107, 88, 16, 187, 11, 180, 209, 97, 161, 137, 52, 212, 230, 147, 115, 43, 7, 24, 61, 145, 87, 238, 123, 28, 141, 147, 55, 120],
    [226, 214, 0, 9, 26, 219, 214, 184, 18, 221, 149, 224, 218, 144, 121, 69, 245, 243, 61, 90, 183, 227, 140, 122, 2, 246, 149, 8, 185, 108, 190, 45],
    [69, 15, 106, 206, 123, 72, 137, 10, 54, 183, 21, 120, 197, 151, 89, 47, 125, 182, 171, 87, 182, 192, 210, 146, 240, 166, 56, 234, 193, 162, 1, 176],
    [107, 41, 14, 116, 8, 92, 109, 71, 204, 5, 240, 246, 168, 98, 108, 141, 178, 218, 37, 170, 225, 49, 11, 20, 119, 205, 81, 41, 18, 199, 104, 20],
    [145, 188, 124, 230, 133, 160, 187, 214, 12, 1, 231, 27, 70, 62, 222, 41, 104, 139, 61, 165, 106, 50, 72, 51, 193, 80, 96, 234, 172, 157, 46, 251],
    [157, 207, 244, 198, 101, 133, 54, 32, 0, 84, 175, 183, 124, 79, 70, 234, 243, 146, 70, 22, 3, 37, 50, 98, 181, 228, 218, 160, 24, 139, 168, 109],
    [183, 254, 216, 191, 38, 51, 27, 253, 7, 141, 13, 156, 231, 178, 13, 48, 203, 12, 228, 99, 14, 195, 97, 134, 10, 54, 18, 136, 31, 214, 240, 239],
    [142, 236, 171, 112, 128, 126, 131, 76, 65, 197, 192, 58, 150, 42, 164, 15, 228, 229, 122, 8, 202, 98, 212, 220, 192, 162, 79, 164, 189, 128, 163, 81],
    [16, 166, 89, 77, 75, 200, 34, 172, 157, 228, 125, 24, 219, 86, 35, 122, 101, 8, 130, 120, 144, 114, 56, 73, 176, 24, 252, 210, 15, 148, 7, 208],
    [92, 246, 168, 226, 169, 216, 117, 53, 199, 237, 82, 129, 172, 137, 135, 23, 58, 91, 198, 161, 165, 45, 248, 102, 77, 38, 145, 224, 80, 46, 125, 145],
    [211, 210, 224, 9, 182, 189, 130, 156, 236, 7, 22, 11, 22, 80, 58, 135, 161, 40, 158, 36, 234, 171, 98, 72, 56, 144, 244, 71, 81, 14, 206, 23],
    [216, 123, 9, 1, 102, 81, 176, 38, 70, 236, 122, 34, 98, 68, 220, 170, 229, 40, 144, 109, 11, 106, 214, 173, 112, 155, 184, 147, 73, 136, 38, 235],
    [52, 105, 213, 216, 63, 112, 229, 29, 48, 84, 94, 185, 51, 172, 19, 170, 201, 243, 102, 52, 158, 50, 19, 248, 201, 217, 159, 86, 68, 166, 128, 228],
    [150, 23, 63, 158, 26, 44, 222, 57, 34, 141, 8, 226, 170, 229, 98, 200, 43, 31, 191, 157, 135, 144, 32, 21, 76, 214, 118, 19, 25, 182, 111, 23],
    [54, 188, 68, 62, 40, 24, 168, 162, 33, 18, 209, 57, 56, 85, 136, 186, 38, 229, 2, 163, 28, 202, 52, 5, 159, 98, 195, 138, 77, 84, 249, 234],
    [221, 170, 235, 0, 154, 248, 8, 46, 254, 188, 12, 103, 36, 156, 197, 14, 143, 178, 54, 234, 255, 246, 104, 198, 10, 231, 45, 186, 133, 6, 69, 243],
    [242, 44, 59, 214, 151, 195, 213, 70, 179, 67, 127, 179, 45, 241, 245, 58, 16, 160, 144, 240, 58, 153, 40, 27, 78, 146, 168, 60, 42, 6, 244, 159],
    [64, 71, 2, 156, 153, 235, 78, 246, 57, 37, 155, 46, 227, 200, 222, 180, 64, 144, 134, 200, 29, 225, 205, 171, 0, 83, 187, 204, 8, 132, 228, 30],
    [120, 76, 9, 17, 150, 204, 66, 113, 217, 144, 160, 41, 67, 63, 64, 175, 149, 33, 201, 85, 225, 18, 122, 80, 253, 214, 30, 76, 171, 183, 127, 29],
    [105, 32, 106, 71, 42, 31, 56, 66, 89, 242, 195, 135, 33, 31, 18, 61, 60, 179, 8, 236, 60, 41, 201, 137, 35, 51, 129, 76, 62, 190, 186, 34],
    [27, 44, 75, 181, 178, 14, 213, 189, 124, 246, 59, 26, 74, 183, 79, 11, 56, 149, 220, 178, 10, 159, 131, 87, 62, 58, 83, 189, 5, 240, 13, 226],
    [49, 97, 41, 61, 171, 193, 207, 57, 98, 22, 36, 14, 40, 197, 39, 140, 93, 59, 96, 173, 218, 241, 30, 195, 29, 113, 82, 47, 235, 227, 154, 207],
    [17, 151, 242, 175, 217, 6, 67, 193, 237, 60, 136, 47, 6, 217, 231, 234, 42, 239, 36, 173, 35, 116, 14, 2, 37, 185, 222, 12, 59, 150, 49, 157],
    [98, 130, 107, 248, 59, 197, 159, 233, 5, 89, 215, 69, 33, 172, 177, 124, 200, 88, 63, 237, 135, 200, 191, 108, 32, 181, 91, 228, 236, 25, 240, 233],
    [45, 78, 89, 45, 116, 112, 89, 119, 129, 55, 100, 231, 243, 61, 130, 113, 204, 111, 91, 177, 40, 165, 149, 60, 136, 40, 40, 126, 72, 168, 159, 155],
    [134, 50, 254, 124, 177, 195, 17, 192, 255, 35, 21, 218, 11, 162, 24, 186, 72, 77, 232, 189, 241, 14, 185, 66, 200, 228, 167, 228, 168, 131, 198, 87],
    [55, 194, 128, 160, 90, 153, 70, 89, 234, 23, 64, 3, 73, 84, 136, 159, 198, 253, 69, 57, 249, 155, 201, 38, 233, 249, 187, 149, 107, 29, 90, 97],
    [249, 63, 53, 204, 65, 63, 189, 122, 123, 197, 60, 228, 232, 23, 118, 233, 189, 197, 233, 207, 187, 80, 155, 63, 191, 182, 170, 89, 104, 122, 17, 36],
    [36, 188, 203, 237, 61, 85, 208, 146, 109, 7, 62, 23, 122, 59, 234, 207, 137, 193, 238, 232, 61, 51, 37, 44, 130, 174, 86, 168, 107, 35, 20, 184],
    [125, 49, 177, 38, 145, 178, 172, 143, 60, 132, 8, 132, 70, 254, 42, 210, 83, 148, 81, 119, 108, 73, 112, 140, 55, 139, 206, 214, 223, 140, 135, 25],
    [5, 143, 197, 8, 75, 99, 85, 160, 96, 153, 191, 239, 61, 232, 227, 96, 52, 64, 70, 220, 90, 71, 2, 109, 228, 116, 112, 185, 170, 187, 91, 253],
    [71, 27, 230, 85, 139, 102, 94, 79, 109, 212, 159, 17, 132, 129, 77, 20, 145, 176, 49, 93, 70, 107, 238, 167, 104, 193, 83, 204, 85, 0, 200, 54],
    [2, 66, 92, 15, 91, 13, 171, 243, 210, 185, 17, 95, 63, 119, 35, 160, 42, 216, 188, 251, 21, 52, 160, 210, 49, 97, 79, 212, 43, 129, 136, 246],
    [31, 125, 17, 13, 67, 245, 60, 52, 9, 66, 47, 161, 138, 254, 199, 50, 153, 252, 217, 222, 74, 147, 77, 42, 219, 253, 225, 186, 61, 108, 186, 22],
    [186, 130, 81, 167, 89, 181, 204, 146, 151, 171, 102, 25, 201, 181, 225, 206, 196, 92, 27, 194, 70, 139, 22, 152, 42, 36, 119, 60, 162, 102, 213, 236],
    [75, 145, 24, 81, 143, 166, 199, 230, 64, 133, 80, 143, 119, 168, 177, 103, 198, 211, 246, 223, 129, 125, 176, 106, 171, 159, 17, 128, 253, 13, 36, 227],
    [162, 135, 129, 169, 197, 60, 6, 41, 152, 243, 49, 158, 56, 30, 244, 103, 36, 171, 148, 124, 166, 176, 12, 184, 86, 222, 56, 1, 15, 90, 57, 111],
    [99, 56, 184, 65, 187, 232, 58, 213, 187, 56, 57, 174, 15, 235, 153, 224, 147, 234, 164, 239, 201, 5, 234, 97, 247, 26, 124, 188, 81, 147, 65, 200],
    [228, 190, 247, 74, 203, 241, 164, 151, 114, 56, 132, 113, 114, 120, 247, 196, 253, 211, 220, 97, 43, 114, 188, 110, 195, 219, 144, 123, 179, 180, 32, 180],
    [76, 163, 138, 9, 236, 244, 252, 153, 227, 117, 240, 246, 190, 250, 68, 53, 121, 194, 10, 1, 113, 177, 250, 78, 148, 124, 50, 134, 154, 197, 72, 124],
    [84, 91, 224, 164, 76, 217, 245, 91, 146, 84, 160, 7, 9, 45, 17, 17, 59, 156, 74, 141, 70, 188, 39, 70, 40, 58, 98, 67, 24, 110, 5, 154],
    [18, 139, 44, 53, 70, 216, 174, 38, 232, 2, 223, 197, 104, 175, 252, 244, 200, 99, 101, 82, 61, 111, 47, 227, 246, 214, 185, 83, 54, 72, 220, 249],
    [190, 147, 205, 227, 220, 68, 193, 77, 81, 135, 196, 115, 24, 254, 46, 52, 241, 24, 0, 119, 25, 158, 101, 67, 56, 110, 94, 40, 44, 15, 254, 228],
    [148, 110, 170, 115, 236, 1, 15, 51, 219, 122, 195, 20, 164, 43, 221, 17, 89, 71, 34, 84, 113, 190, 52, 195, 201, 130, 43, 219, 56, 243, 171, 93],
    [9, 111, 7, 37, 65, 54, 109, 13, 100, 50, 72, 158, 179, 50, 56, 4, 3, 181, 63, 175, 127, 254, 144, 179, 131, 70, 79, 152, 106, 86, 56, 52],
    [210, 75, 44, 173, 189, 98, 61, 79, 238, 235, 155, 28, 86, 216, 119, 134, 228, 53, 113, 77, 139, 87, 60, 253, 47, 156, 109, 51, 227, 213, 208, 51],
    [221, 86, 155, 250, 204, 163, 66, 226, 151, 217, 143, 207, 165, 124, 91, 221, 196, 23, 182, 227, 202, 25, 184, 244, 249, 176, 66, 133, 216, 153, 73, 46],
    [75, 198, 170, 92, 16, 215, 196, 154, 107, 119, 56, 187, 108, 141, 246, 104, 40, 27, 206, 163, 191, 183, 86, 35, 21, 137, 215, 39, 50, 49, 108, 169],
    [149, 196, 172, 19, 226, 61, 81, 221, 150, 204, 190, 81, 196, 115, 249, 105, 0, 154, 161, 185, 103, 50, 46, 81, 180, 250, 90, 127, 34, 191, 181, 68],
    [174, 140, 47, 204, 213, 68, 18, 102, 221, 9, 110, 206, 198, 76, 56, 140, 75, 207, 110, 107, 112, 206, 77, 241, 207, 66, 144, 85, 248, 234, 34, 133],
    [116, 85, 164, 41, 43, 173, 250, 122, 215, 244, 132, 247, 241, 171, 74, 98, 202, 204, 71, 157, 19, 49, 0, 123, 83, 55, 141, 122, 220, 134, 85, 70],
    [62, 247, 250, 168, 160, 38, 137, 143, 175, 79, 43, 240, 163, 31, 140, 220, 151, 179, 140, 31, 27, 20, 9, 24, 146, 87, 121, 35, 154, 33, 58, 20],
    [130, 109, 11, 54, 69, 232, 110, 33, 195, 112, 98, 7, 89, 194, 62, 128, 163, 241, 172, 23, 39, 171, 217, 19, 179, 213, 179, 167, 186, 100, 225, 52],
    [190, 203, 206, 102, 131, 42, 142, 52, 231, 219, 218, 124, 41, 31, 165, 158, 63, 20, 157, 185, 123, 129, 236, 215, 174, 172, 108, 107, 202, 113, 201, 55],
    [74, 74, 71, 168, 248, 184, 125, 230, 92, 68, 154, 70, 121, 38, 10, 110, 65, 156, 56, 245, 179, 122, 228, 124, 220, 157, 250, 140, 55, 200, 151, 48],
    [45, 80, 157, 208, 222, 107, 247, 152, 171, 139, 52, 226, 90, 36, 26, 84, 55, 246, 177, 48, 84, 144, 87, 162, 133, 32, 41, 49, 22, 236, 115, 217],
    [53, 250, 234, 233, 155, 90, 229, 198, 93, 59, 122, 140, 92, 210, 144, 203, 74, 63, 69, 141, 186, 230, 163, 240, 137, 28, 15, 160, 177, 176, 1, 79],
    [69, 10, 132, 203, 181, 0, 34, 189, 237, 51, 253, 63, 203, 43, 200, 1, 157, 245, 129, 96, 15, 94, 26, 198, 126, 95, 126, 14, 131, 25, 102, 3],
    [75, 98, 80, 4, 63, 230, 174, 149, 201, 218, 16, 183, 162, 111, 30, 166, 30, 218, 73, 249, 115, 222, 153, 181, 194, 251, 186, 215, 82, 51, 243, 110],
    [128, 69, 220, 7, 3, 167, 205, 160, 39, 151, 104, 169, 150, 2, 86, 246, 5, 185, 44, 2, 76, 216, 220, 19, 144, 214, 233, 228, 173, 206, 46, 181],
    [110, 0, 202, 22, 228, 115, 95, 57, 195, 210, 22, 214, 109, 203, 125, 173, 97, 229, 252, 205, 220, 102, 36, 140, 170, 156, 94, 89, 130, 115, 239, 124],
    [93, 71, 4, 60, 186, 192, 205, 121, 235, 255, 111, 16, 108, 243, 30, 60, 67, 220, 87, 209, 65, 136, 74, 187, 193, 141, 250, 74, 99, 27, 172, 26],
    [75, 179, 31, 63, 6, 25, 22, 22, 153, 52, 21, 171, 134, 179, 182, 135, 41, 163, 134, 132, 76, 220, 105, 214, 95, 63, 136, 203, 64, 241, 163, 66],
    [222, 202, 166, 192, 114, 190, 135, 181, 159, 85, 61, 129, 77, 170, 144, 207, 43, 183, 142, 83, 174, 119, 242, 93, 120, 147, 165, 168, 46, 15, 173, 246],
    [144, 135, 58, 237, 194, 164, 251, 54, 79, 225, 7, 32, 183, 128, 165, 86, 100, 176, 52, 254, 63, 169, 168, 157, 186, 113, 180, 74, 0, 167, 98, 49],
    [247, 51, 177, 250, 42, 227, 72, 225, 142, 32, 34, 235, 238, 209, 214, 60, 33, 193, 235, 2, 199, 128, 113, 12, 93, 53, 138, 129, 93, 254, 154, 253],
    [41, 126, 72, 121, 185, 131, 74, 92, 23, 237, 27, 98, 4, 26, 106, 24, 123, 142, 9, 247, 185, 244, 58, 190, 7, 39, 228, 162, 82, 106, 95, 37],
    [83, 168, 217, 207, 78, 128, 98, 133, 171, 70, 152, 192, 37, 89, 100, 147, 222, 156, 212, 247, 253, 93, 166, 190, 103, 198, 254, 9, 191, 25, 178, 53],
    [235, 1, 250, 135, 189, 98, 149, 179, 159, 155, 31, 172, 71, 60, 186, 166, 14, 151, 101, 162, 228, 151, 213, 4, 84, 152, 91, 174, 224, 206, 51, 12],
    [220, 154, 178, 24, 123, 244, 42, 247, 86, 186, 46, 231, 193, 115, 105, 2, 185, 127, 102, 166, 63, 182, 82, 237, 57, 186, 186, 53, 88, 165, 62, 136],
    [32, 238, 191, 139, 236, 190, 191, 126, 90, 230, 92, 6, 251, 112, 146, 52, 142, 13, 39, 166, 54, 205, 46, 124, 66, 44, 114, 24, 50, 165, 138, 101],
    [72, 6, 246, 246, 157, 196, 22, 15, 4, 180, 250, 59, 49, 177, 16, 74, 130, 22, 236, 95, 24, 149, 224, 108, 24, 221, 55, 86, 247, 227, 133, 154],
    [247, 145, 99, 50, 151, 93, 8, 84, 173, 225, 82, 245, 126, 163, 55, 187, 140, 211, 193, 36, 235, 127, 21, 147, 62, 146, 29, 237, 153, 69, 13, 27],
    [2, 177, 22, 105, 215, 183, 27, 199, 227, 237, 75, 179, 111, 227, 207, 253, 181, 179, 241, 151, 143, 207, 57, 93, 165, 68, 26, 164, 53, 98, 243, 2],
    [65, 187, 183, 153, 155, 223, 125, 239, 106, 241, 70, 6, 24, 233, 17, 163, 213, 105, 94, 62, 16, 60, 135, 221, 82, 117, 87, 76, 117, 252, 76, 214],
    [10, 221, 191, 119, 179, 145, 34, 55, 98, 195, 235, 88, 162, 226, 185, 61, 225, 155, 109, 217, 241, 85, 0, 45, 226, 112, 190, 53, 10, 238, 78, 125],
    [192, 222, 146, 234, 91, 252, 22, 176, 12, 2, 119, 229, 54, 191, 42, 242, 139, 113, 252, 131, 110, 17, 186, 105, 121, 4, 63, 221, 159, 253, 12, 252],
    [15, 103, 89, 153, 174, 89, 120, 42, 68, 195, 195, 228, 37, 87, 231, 2, 160, 46, 38, 171, 236, 229, 118, 117, 41, 11, 99, 20, 240, 159, 229, 54],
    [196, 164, 0, 17, 120, 89, 2, 216, 132, 187, 245, 97, 100, 26, 255, 12, 9, 101, 201, 250, 209, 83, 135, 39, 238, 31, 142, 168, 60, 204, 96, 134],
    [240, 43, 203, 54, 176, 232, 202, 149, 245, 150, 246, 158, 9, 116, 190, 143, 32, 141, 6, 73, 159, 251, 155, 10, 148, 164, 44, 214, 41, 51, 179, 59],
    [170, 52, 126, 185, 77, 201, 193, 8, 191, 217, 150, 86, 93, 208, 152, 201, 51, 165, 59, 88, 136, 100, 94, 9, 94, 232, 65, 145, 9, 211, 242, 75],
    [62, 71, 237, 153, 13, 49, 240, 254, 176, 167, 119, 28, 114, 209, 50, 15, 173, 85, 88, 20, 247, 129, 149, 110, 252, 137, 218, 136, 79, 246, 61, 64],
    [76, 38, 1, 151, 110, 230, 232, 169, 211, 114, 152, 227, 105, 231, 105, 78, 19, 160, 145, 224, 188, 177, 196, 181, 190, 218, 37, 17, 3, 235, 61, 86],
    [18, 214, 251, 187, 27, 37, 92, 133, 157, 226, 229, 48, 188, 146, 179, 110, 121, 44, 29, 6, 79, 253, 243, 152, 110, 187, 87, 104, 191, 181, 52, 144],
    [86, 3, 27, 238, 50, 240, 245, 248, 91, 104, 102, 10, 122, 99, 71, 45, 64, 202, 167, 209, 85, 31, 43, 197, 245, 35, 39, 119, 209, 191, 112, 81],
    [11, 20, 156, 72, 115, 184, 22, 168, 109, 49, 102, 170, 9, 19, 153, 162, 124, 10, 218, 229, 251, 76, 164, 157, 2, 236, 247, 183, 145, 216, 184, 237],
    [31, 47, 196, 150, 216, 255, 249, 144, 127, 6, 183, 115, 123, 205, 241, 194, 85, 103, 189, 0, 188, 192, 146, 48, 222, 42, 140, 227, 26, 104, 180, 15],
    [203, 90, 43, 225, 18, 70, 167, 124, 230, 178, 189, 148, 98, 172, 35, 229, 120, 226, 72, 174, 218, 50, 125, 127, 46, 127, 44, 41, 21, 249, 9, 9],
    [189, 88, 118, 36, 59, 17, 182, 114, 241, 229, 136, 52, 122, 93, 1, 172, 153, 194, 57, 17, 239, 89, 147, 210, 246, 45, 90, 140, 158, 191, 196, 249],
    [189, 98, 115, 118, 189, 200, 79, 203, 17, 166, 142, 202, 23, 173, 235, 174, 59, 109, 77, 203, 219, 37, 20, 65, 17, 221, 93, 155, 220, 169, 247, 18],
    [37, 8, 175, 13, 28, 196, 184, 55, 8, 208, 23, 89, 70, 108, 242, 91, 184, 44, 129, 166, 204, 173, 120, 197, 20, 60, 221, 187, 198, 83, 234, 102],
    [107, 195, 184, 234, 234, 83, 128, 229, 34, 255, 125, 247, 115, 105, 137, 181, 227, 255, 245, 105, 186, 117, 0, 59, 230, 58, 142, 122, 185, 200, 18, 62],
    [51, 252, 70, 168, 138, 78, 105, 50, 183, 172, 9, 20, 176, 221, 124, 205, 163, 80, 253, 89, 70, 210, 223, 147, 235, 152, 157, 225, 245, 188, 156, 200],
    [113, 207, 17, 129, 159, 79, 205, 155, 254, 201, 103, 204, 87, 51, 213, 47, 31, 136, 227, 107, 255, 31, 63, 0, 32, 146, 231, 18, 26, 156, 110, 245],
    [51, 56, 185, 90, 109, 15, 40, 123, 78, 148, 69, 124, 45, 100, 24, 245, 213, 76, 86, 49, 13, 229, 30, 32, 187, 37, 24, 215, 93, 36, 35, 134],
    [229, 238, 23, 115, 167, 20, 76, 132, 162, 26, 60, 232, 93, 99, 102, 218, 177, 79, 209, 159, 242, 130, 146, 57, 157, 1, 51, 179, 145, 167, 122, 141],
    [229, 59, 165, 189, 230, 170, 220, 241, 181, 95, 51, 188, 156, 153, 207, 108, 214, 251, 36, 118, 249, 189, 93, 163, 224, 52, 52, 85, 86, 52, 122, 9],
    [245, 100, 195, 107, 205, 170, 144, 197, 102, 121, 182, 22, 101, 245, 204, 6, 199, 69, 181, 236, 78, 226, 139, 104, 63, 242, 57, 98, 60, 153, 109, 139],
    [40, 62, 57, 235, 224, 226, 245, 149, 24, 74, 170, 138, 206, 211, 205, 140, 131, 228, 169, 76, 208, 14, 179, 96, 175, 169, 140, 183, 119, 109, 83, 83],
    [5, 44, 14, 175, 118, 41, 74, 55, 232, 144, 31, 216, 186, 173, 162, 127, 32, 25, 167, 130, 179, 14, 225, 198, 247, 112, 60, 112, 51, 200, 170, 14],
    [220, 139, 37, 81, 30, 43, 85, 105, 43, 149, 220, 161, 110, 142, 103, 157, 96, 161, 151, 236, 13, 235, 145, 82, 250, 135, 86, 42, 64, 118, 142, 128],
    [1, 67, 50, 21, 22, 13, 51, 46, 145, 253, 15, 92, 206, 253, 114, 238, 60, 108, 87, 32, 37, 217, 105, 217, 36, 88, 155, 81, 114, 52, 224, 156],
    [116, 126, 163, 205, 74, 204, 63, 177, 65, 216, 88, 119, 0, 10, 191, 187, 206, 166, 142, 85, 52, 13, 232, 162, 116, 144, 111, 169, 185, 103, 42, 4],
    [71, 55, 30, 217, 116, 26, 105, 123, 106, 25, 148, 147, 4, 139, 61, 65, 84, 47, 189, 153, 138, 251, 35, 105, 229, 67, 180, 142, 40, 242, 188, 110],
    [145, 145, 138, 120, 7, 104, 122, 142, 81, 21, 147, 11, 63, 242, 3, 3, 126, 192, 132, 77, 212, 235, 26, 0, 34, 185, 14, 133, 100, 188, 51, 113],
    [191, 77, 62, 115, 197, 192, 147, 170, 81, 242, 156, 133, 234, 49, 181, 106, 163, 40, 224, 110, 235, 249, 187, 30, 114, 201, 83, 82, 132, 134, 124, 135],
    [77, 52, 246, 98, 105, 13, 140, 118, 164, 239, 65, 123, 164, 172, 85, 225, 189, 146, 142, 189, 27, 229, 220, 230, 69, 139, 132, 128, 95, 152, 83, 158],
    [83, 63, 239, 164, 238, 220, 224, 16, 95, 192, 231, 223, 233, 216, 157, 36, 228, 13, 196, 157, 2, 63, 146, 213, 136, 100, 232, 121, 179, 60, 97, 3],
    [48, 235, 175, 144, 67, 126, 152, 158, 157, 58, 106, 147, 209, 198, 119, 105, 21, 86, 33, 128, 101, 78, 117, 11, 243, 126, 89, 208, 168, 138, 5, 251],
    [200, 168, 186, 100, 187, 64, 62, 206, 147, 28, 17, 108, 37, 173, 208, 164, 21, 139, 78, 35, 14, 21, 229, 185, 20, 15, 190, 239, 88, 148, 248, 146],
    [24, 212, 236, 193, 79, 166, 67, 55, 254, 6, 102, 220, 17, 105, 93, 244, 218, 64, 198, 124, 70, 79, 253, 21, 110, 214, 132, 239, 147, 59, 36, 25],
    [102, 147, 41, 171, 159, 255, 50, 94, 56, 157, 63, 51, 1, 170, 99, 212, 211, 239, 221, 55, 152, 100, 220, 202, 145, 1, 124, 67, 133, 160, 202, 107],
    [17, 70, 181, 185, 251, 94, 175, 73, 186, 205, 232, 108, 162, 218, 20, 112, 94, 6, 71, 154, 21, 96, 140, 171, 64, 85, 100, 138, 87, 235, 105, 7],
    [8, 6, 255, 30, 5, 165, 234, 116, 231, 172, 148, 38, 122, 151, 209, 71, 45, 126, 8, 79, 15, 251, 237, 241, 146, 52, 63, 107, 124, 126, 154, 197],
    [205, 82, 243, 142, 31, 178, 135, 165, 35, 30, 197, 56, 233, 51, 130, 227, 131, 127, 154, 170, 66, 96, 41, 101, 227, 225, 249, 69, 228, 35, 164, 250],
    [238, 246, 24, 248, 169, 62, 7, 23, 6, 158, 133, 61, 107, 107, 158, 253, 224, 89, 218, 162, 109, 251, 35, 6, 138, 237, 145, 46, 81, 219, 25, 53],
    [29, 117, 44, 175, 128, 41, 197, 63, 110, 30, 142, 124, 251, 166, 68, 141, 119, 232, 148, 191, 172, 73, 29, 46, 49, 72, 146, 187, 7, 50, 228, 142],
    [1, 148, 124, 56, 199, 85, 118, 135, 101, 226, 64, 20, 164, 214, 118, 241, 33, 220, 16, 245, 138, 206, 110, 35, 131, 188, 6, 166, 172, 100, 239, 133],
    [146, 93, 22, 142, 46, 87, 82, 172, 87, 107, 1, 69, 16, 125, 112, 177, 227, 207, 155, 136, 118, 126, 202, 44, 201, 99, 2, 14, 55, 58, 222, 50],
    [186, 53, 193, 112, 114, 148, 23, 241, 73, 158, 8, 134, 231, 225, 47, 205, 180, 171, 0, 173, 65, 17, 16, 174, 30, 136, 140, 118, 109, 78, 215, 13],
    [226, 118, 111, 237, 157, 36, 148, 127, 254, 149, 60, 193, 22, 216, 13, 124, 14, 81, 10, 33, 215, 248, 59, 236, 123, 82, 58, 252, 10, 116, 132, 244],
    [74, 21, 158, 8, 131, 39, 188, 77, 122, 193, 78, 34, 193, 182, 85, 28, 184, 230, 121, 62, 103, 131, 15, 77, 112, 21, 172, 198, 28, 93, 124, 76],
    [121, 43, 55, 124, 143, 129, 69, 5, 106, 174, 215, 107, 223, 151, 157, 250, 112, 25, 213, 249, 10, 226, 123, 106, 221, 228, 42, 24, 98, 138, 57, 151],
    [71, 6, 251, 185, 206, 92, 201, 180, 138, 39, 118, 131, 94, 103, 136, 221, 67, 17, 103, 229, 243, 135, 119, 32, 84, 111, 111, 177, 161, 113, 35, 48],
    [209, 14, 219, 131, 112, 230, 3, 30, 11, 132, 233, 231, 227, 112, 41, 66, 119, 247, 177, 171, 165, 185, 47, 108, 45, 104, 251, 208, 177, 49, 212, 154],
    [147, 71, 28, 108, 35, 18, 21, 2, 213, 157, 126, 110, 144, 142, 19, 156, 216, 119, 160, 186, 230, 110, 90, 117, 63, 171, 184, 64, 8, 156, 248, 54],
    [197, 200, 184, 121, 22, 46, 224, 245, 110, 184, 200, 251, 218, 238, 59, 145, 251, 35, 73, 188, 255, 128, 130, 160, 249, 70, 225, 45, 127, 22, 238, 76],
    [199, 198, 24, 106, 52, 212, 174, 105, 85, 83, 115, 235, 30, 78, 215, 83, 43, 75, 0, 146, 159, 104, 38, 218, 37, 246, 20, 237, 178, 26, 42, 162],
    [108, 157, 213, 35, 212, 58, 137, 193, 85, 99, 220, 120, 124, 145, 157, 15, 179, 105, 219, 216, 177, 219, 150, 197, 134, 159, 215, 6, 156, 153, 239, 177],
    [29, 63, 43, 117, 83, 50, 90, 75, 5, 44, 163, 11, 49, 124, 252, 234, 170, 6, 111, 163, 209, 197, 56, 137, 105, 175, 247, 1, 131, 195, 9, 219],
    [241, 249, 59, 165, 229, 137, 186, 228, 201, 60, 95, 183, 135, 240, 60, 161, 119, 117, 118, 232, 32, 150, 227, 229, 152, 16, 138, 88, 199, 254, 191, 152],
    [158, 48, 14, 25, 47, 185, 2, 117, 128, 71, 196, 68, 20, 90, 45, 70, 242, 115, 63, 86, 171, 40, 220, 150, 88, 247, 193, 56, 27, 253, 79, 51],
    [222, 97, 182, 98, 4, 209, 94, 235, 227, 141, 156, 201, 228, 212, 158, 157, 50, 95, 185, 173, 60, 146, 89, 245, 15, 102, 188, 58, 238, 177, 243, 167],
    [116, 236, 222, 141, 254, 71, 231, 73, 162, 185, 94, 112, 116, 101, 22, 83, 199, 47, 121, 199, 22, 221, 120, 91, 246, 219, 99, 112, 117, 71, 18, 58],
    [241, 11, 65, 249, 213, 38, 99, 194, 132, 180, 217, 5, 117, 35, 202, 117, 31, 4, 91, 236, 99, 10, 69, 151, 65, 231, 62, 9, 137, 120, 39, 200],
    [11, 38, 42, 59, 199, 81, 156, 128, 196, 152, 134, 136, 150, 45, 222, 129, 99, 183, 225, 51, 13, 250, 229, 24, 105, 90, 135, 162, 77, 212, 187, 185],
    [132, 11, 159, 45, 241, 14, 51, 96, 172, 17, 183, 195, 211, 191, 112, 93, 255, 172, 4, 54, 78, 166, 4, 9, 23, 126, 215, 93, 255, 172, 24, 21],
    [114, 86, 90, 59, 216, 33, 161, 177, 132, 192, 115, 194, 18, 29, 241, 121, 58, 248, 192, 9, 38, 235, 24, 53, 229, 114, 219, 69, 190, 131, 191, 42],
    [187, 137, 130, 43, 44, 79, 2, 47, 111, 71, 141, 119, 162, 235, 66, 217, 69, 82, 59, 77, 14, 103, 40, 20, 123, 243, 36, 113, 199, 155, 158, 224],
    [134, 14, 84, 241, 21, 10, 175, 60, 74, 40, 145, 232, 192, 172, 73, 145, 117, 95, 153, 92, 137, 159, 203, 25, 232, 87, 16, 119, 104, 70, 31, 59],
    [246, 170, 121, 222, 152, 152, 33, 21, 121, 118, 213, 165, 110, 172, 126, 188, 74, 128, 25, 200, 121, 69, 131, 221, 154, 60, 191, 51, 12, 206, 237, 92],
    [69, 120, 237, 40, 119, 105, 121, 138, 4, 53, 196, 29, 192, 155, 145, 215, 79, 176, 64, 4, 202, 8, 220, 205, 210, 73, 233, 170, 74, 251, 198, 162],
    [138, 165, 167, 0, 204, 249, 77, 136, 169, 82, 230, 159, 75, 99, 226, 55, 64, 88, 221, 79, 219, 69, 32, 55, 103, 46, 34, 204, 200, 14, 77, 250],
    [60, 183, 154, 31, 103, 55, 10, 78, 48, 165, 133, 128, 40, 203, 37, 174, 122, 196, 48, 77, 165, 173, 185, 144, 14, 56, 76, 153, 148, 196, 75, 167],
    [129, 69, 38, 110, 48, 160, 5, 68, 119, 104, 124, 112, 104, 183, 76, 162, 141, 232, 247, 150, 100, 41, 197, 112, 135, 64, 253, 88, 1, 131, 151, 176],
    [198, 32, 145, 61, 173, 134, 10, 42, 119, 61, 157, 86, 12, 44, 237, 37, 3, 246, 249, 226, 197, 92, 205, 101, 8, 59, 240, 83, 45, 96, 98, 97],
    [199, 104, 109, 255, 183, 66, 220, 101, 177, 255, 94, 94, 102, 141, 112, 25, 20, 35, 247, 19, 231, 3, 72, 188, 222, 101, 147, 131, 103, 212, 85, 172],
    [148, 44, 170, 35, 74, 202, 87, 196, 107, 45, 197, 73, 83, 249, 7, 35, 40, 57, 154, 67, 165, 24, 68, 85, 28, 142, 87, 14, 163, 138, 15, 133],
    [172, 16, 59, 38, 240, 18, 31, 100, 149, 97, 16, 229, 94, 88, 85, 251, 145, 37, 85, 174, 53, 200, 165, 131, 10, 88, 70, 244, 163, 238, 154, 56],
    [206, 125, 99, 7, 85, 99, 62, 4, 72, 15, 78, 21, 176, 52, 205, 254, 155, 33, 70, 17, 147, 63, 158, 111, 152, 84, 228, 253, 12, 38, 180, 80],
    [53, 133, 237, 13, 99, 122, 222, 172, 151, 222, 241, 75, 40, 24, 0, 22, 233, 35, 87, 208, 212, 240, 182, 232, 108, 72, 33, 197, 7, 217, 255, 150],
    [69, 37, 9, 14, 54, 192, 64, 159, 107, 212, 96, 133, 25, 74, 193, 177, 204, 41, 70, 73, 16, 48, 9, 48, 165, 88, 47, 191, 84, 103, 255, 19],
    [120, 38, 175, 244, 45, 175, 131, 1, 174, 118, 231, 209, 132, 201, 18, 244, 122, 177, 29, 241, 114, 228, 143, 203, 121, 229, 103, 44, 72, 92, 133, 48],
    [250, 111, 41, 245, 122, 183, 72, 216, 249, 88, 87, 60, 21, 204, 22, 159, 9, 43, 62, 112, 132, 187, 200, 4, 147, 53, 36, 121, 198, 246, 93, 87],
    [121, 31, 138, 147, 82, 102, 152, 61, 43, 163, 59, 156, 252, 99, 57, 155, 22, 218, 6, 175, 66, 195, 72, 161, 148, 152, 250, 131, 170, 210, 22, 90],
    [198, 40, 196, 209, 196, 191, 181, 125, 51, 112, 97, 82, 31, 232, 90, 135, 235, 169, 196, 179, 228, 110, 160, 222, 80, 175, 252, 250, 135, 96, 204, 120],
    [118, 112, 70, 81, 144, 110, 235, 229, 68, 208, 73, 175, 72, 192, 69, 141, 69, 245, 134, 245, 94, 61, 200, 124, 160, 129, 61, 18, 57, 216, 96, 234],
    [27, 70, 178, 99, 21, 247, 29, 80, 98, 140, 184, 18, 78, 19, 184, 224, 171, 178, 99, 137, 147, 235, 222, 26, 102, 12, 19, 144, 6, 164, 197, 156],
    [46, 44, 214, 53, 175, 142, 47, 221, 244, 50, 32, 172, 74, 113, 153, 139, 49, 119, 220, 209, 206, 60, 81, 107, 170, 96, 188, 6, 68, 96, 79, 56],
    [154, 106, 173, 100, 186, 231, 82, 45, 139, 108, 189, 230, 116, 198, 38, 133, 99, 221, 39, 247, 79, 79, 229, 181, 92, 102, 148, 43, 116, 76, 115, 153],
    [146, 137, 149, 193, 41, 153, 168, 130, 157, 112, 246, 141, 149, 221, 82, 244, 196, 63, 142, 172, 14, 77, 70, 120, 201, 9, 18, 114, 59, 81, 100, 112],
    [27, 179, 150, 160, 47, 26, 25, 64, 13, 36, 18, 76, 90, 251, 112, 75, 198, 88, 103, 231, 43, 78, 167, 234, 229, 180, 43, 151, 157, 51, 72, 78],
    [250, 174, 254, 66, 157, 160, 155, 29, 214, 31, 9, 217, 6, 46, 57, 253, 131, 110, 246, 38, 252, 175, 43, 113, 37, 224, 125, 156, 200, 240, 1, 186],
    [115, 55, 196, 191, 205, 173, 22, 35, 226, 113, 126, 155, 111, 160, 28, 58, 29, 85, 46, 132, 136, 211, 182, 133, 97, 153, 114, 103, 241, 25, 203, 166],
    [209, 47, 44, 202, 112, 188, 86, 40, 228, 120, 25, 115, 84, 19, 245, 230, 85, 189, 230, 59, 24, 113, 86, 132, 75, 91, 75, 40, 33, 137, 136, 38],
    [115, 166, 85, 78, 1, 81, 247, 232, 108, 224, 43, 21, 155, 2, 129, 20, 210, 58, 236, 196, 19, 0, 133, 239, 70, 209, 3, 95, 217, 98, 109, 161],
    [150, 231, 36, 171, 4, 241, 234, 83, 134, 2, 161, 51, 154, 150, 169, 52, 158, 188, 114, 9, 217, 83, 24, 191, 78, 81, 2, 22, 87, 138, 230, 151],
    [53, 150, 238, 23, 84, 107, 192, 114, 238, 45, 234, 112, 97, 214, 61, 111, 205, 42, 9, 188, 81, 229, 243, 231, 146, 204, 46, 166, 139, 21, 127, 244],
    [137, 212, 8, 97, 58, 36, 77, 111, 45, 125, 88, 102, 130, 113, 216, 225, 50, 81, 60, 164, 0, 0, 86, 164, 189, 172, 41, 87, 200, 146, 6, 176],
    [29, 176, 172, 4, 114, 73, 98, 28, 142, 29, 92, 212, 41, 89, 159, 24, 166, 92, 139, 113, 11, 230, 180, 125, 148, 58, 189, 86, 169, 248, 154, 91],
    [81, 60, 244, 13, 197, 185, 169, 97, 151, 6, 189, 53, 169, 15, 64, 148, 44, 56, 249, 90, 76, 237, 46, 10, 49, 253, 145, 238, 139, 157, 107, 200],
    [200, 224, 105, 246, 45, 150, 16, 184, 188, 48, 149, 149, 83, 74, 35, 202, 246, 166, 25, 240, 106, 7, 206, 172, 119, 49, 67, 90, 75, 79, 98, 186],
    [67, 183, 11, 150, 5, 119, 208, 122, 12, 135, 174, 113, 11, 211, 93, 84, 245, 122, 23, 238, 129, 54, 189, 236, 73, 79, 51, 7, 54, 193, 119, 154],
    [47, 2, 181, 160, 8, 24, 224, 84, 3, 118, 190, 1, 73, 247, 7, 169, 248, 89, 160, 101, 169, 197, 217, 235, 20, 114, 9, 142, 71, 188, 200, 127],
    [61, 210, 117, 209, 229, 192, 243, 133, 164, 60, 204, 207, 153, 134, 62, 145, 144, 218, 212, 102, 54, 44, 223, 224, 100, 129, 108, 9, 174, 248, 222, 219],
    [165, 16, 155, 238, 157, 94, 146, 208, 250, 205, 192, 31, 98, 100, 99, 217, 190, 191, 167, 190, 125, 101, 41, 138, 206, 34, 238, 36, 226, 26, 46, 92],
    [95, 0, 127, 148, 185, 105, 44, 136, 245, 1, 193, 4, 169, 201, 139, 140, 199, 89, 45, 132, 85, 18, 11, 147, 115, 252, 9, 235, 211, 131, 194, 181],
    [210, 6, 129, 37, 193, 242, 13, 6, 183, 245, 98, 205, 231, 197, 10, 64, 210, 151, 89, 248, 149, 73, 91, 152, 163, 50, 72, 69, 227, 198, 234, 223],
    [164, 100, 231, 108, 131, 220, 31, 48, 33, 211, 51, 199, 212, 233, 44, 31, 138, 112, 35, 210, 207, 43, 190, 91, 217, 59, 157, 159, 52, 175, 147, 95],
    [97, 227, 88, 174, 153, 227, 179, 194, 125, 173, 126, 59, 211, 235, 196, 117, 43, 143, 218, 226, 250, 171, 189, 84, 134, 246, 191, 223, 77, 47, 2, 192],
    [138, 11, 70, 253, 104, 171, 209, 49, 1, 175, 10, 4, 248, 11, 81, 255, 63, 202, 4, 54, 39, 221, 122, 94, 244, 149, 65, 223, 161, 169, 84, 58],
    [120, 185, 78, 30, 207, 54, 44, 153, 171, 105, 246, 157, 239, 209, 25, 63, 123, 26, 141, 217, 254, 48, 232, 13, 241, 53, 122, 146, 190, 190, 166, 230],
    [232, 20, 87, 65, 69, 207, 183, 27, 133, 118, 180, 177, 203, 79, 55, 97, 92, 72, 249, 38, 186, 218, 211, 228, 5, 98, 229, 117, 109, 207, 250, 171],
    [17, 12, 50, 82, 181, 196, 250, 62, 24, 244, 34, 87, 29, 177, 61, 245, 150, 48, 255, 72, 117, 59, 128, 146, 4, 159, 86, 144, 55, 161, 251, 184],
    [206, 254, 177, 28, 119, 122, 166, 142, 165, 192, 164, 128, 0, 111, 137, 32, 214, 165, 196, 236, 83, 247, 227, 137, 132, 130, 112, 116, 149, 32, 154, 122],
    [162, 43, 164, 21, 163, 200, 211, 196, 106, 126, 33, 91, 199, 62, 113, 125, 24, 0, 226, 32, 90, 170, 120, 6, 91, 59, 113, 72, 49, 254, 34, 168],
    [166, 113, 180, 151, 140, 16, 105, 131, 139, 101, 142, 71, 108, 227, 1, 15, 233, 215, 31, 231, 83, 122, 55, 32, 56, 184, 10, 16, 1, 209, 142, 69],
    [189, 24, 169, 6, 203, 239, 20, 69, 32, 200, 72, 127, 136, 48, 61, 237, 140, 43, 218, 106, 131, 106, 137, 131, 20, 73, 189, 33, 179, 222, 24, 251],
    [47, 55, 70, 167, 98, 84, 128, 97, 155, 93, 175, 130, 161, 96, 187, 205, 33, 48, 11, 163, 197, 196, 246, 168, 128, 102, 11, 204, 101, 27, 133, 65],
    [27, 161, 115, 41, 211, 250, 87, 98, 40, 204, 25, 10, 97, 7, 210, 87, 6, 125, 199, 53, 40, 83, 217, 255, 1, 236, 185, 199, 72, 239, 176, 87],
    [60, 44, 81, 13, 63, 142, 188, 249, 64, 8, 172, 142, 134, 253, 1, 205, 11, 43, 111, 126, 167, 142, 74, 6, 7, 199, 111, 59, 250, 50, 148, 183],
    [178, 6, 184, 189, 56, 210, 220, 96, 247, 16, 69, 83, 133, 231, 19, 95, 229, 177, 250, 59, 95, 78, 69, 232, 196, 183, 69, 229, 18, 206, 28, 126],
    [244, 168, 181, 84, 41, 44, 18, 103, 69, 27, 177, 2, 175, 161, 241, 247, 113, 22, 27, 190, 168, 175, 52, 168, 163, 14, 150, 80, 227, 88, 115, 158],
    [230, 8, 136, 252, 219, 38, 20, 206, 228, 18, 107, 165, 220, 203, 202, 114, 20, 249, 255, 28, 12, 232, 145, 5, 55, 96, 118, 139, 219, 249, 134, 195],
    [66, 206, 44, 220, 106, 196, 152, 15, 113, 95, 108, 233, 104, 47, 51, 3, 144, 175, 6, 6, 62, 62, 215, 215, 244, 186, 137, 194, 67, 253, 46, 124],
    [14, 8, 87, 85, 85, 127, 231, 4, 178, 29, 52, 132, 218, 224, 113, 82, 200, 168, 205, 209, 159, 79, 224, 180, 32, 25, 26, 14, 209, 225, 255, 158],
    [58, 229, 163, 217, 99, 179, 102, 173, 83, 162, 161, 214, 213, 193, 5, 40, 196, 156, 220, 122, 75, 27, 189, 100, 193, 157, 57, 58, 116, 134, 11, 143],
    [124, 108, 114, 229, 181, 200, 45, 27, 117, 123, 164, 163, 35, 165, 16, 137, 73, 142, 64, 215, 114, 53, 45, 234, 141, 17, 90, 161, 98, 92, 230, 75],
    [106, 37, 0, 136, 108, 196, 254, 250, 35, 234, 21, 167, 239, 136, 89, 30, 15, 5, 23, 151, 175, 130, 191, 209, 157, 177, 174, 144, 166, 111, 123, 114],
    [119, 188, 147, 4, 64, 210, 192, 73, 226, 197, 89, 89, 120, 220, 217, 164, 131, 2, 3, 39, 205, 212, 56, 178, 52, 7, 39, 147, 153, 253, 191, 61],
    [108, 225, 136, 104, 33, 63, 5, 149, 186, 116, 212, 81, 195, 247, 127, 169, 140, 36, 33, 88, 130, 6, 158, 240, 9, 10, 150, 91, 37, 82, 109, 112],
    [26, 40, 84, 218, 45, 178, 70, 171, 96, 235, 7, 70, 77, 43, 230, 226, 77, 96, 185, 201, 38, 81, 29, 231, 147, 159, 186, 22, 142, 193, 214, 138],
    [96, 96, 247, 50, 3, 221, 73, 191, 39, 102, 90, 246, 127, 170, 50, 59, 234, 106, 165, 105, 253, 133, 53, 170, 208, 128, 178, 22, 219, 203, 231, 205],
    [20, 255, 75, 113, 40, 236, 202, 209, 20, 187, 130, 186, 12, 210, 95, 196, 197, 253, 135, 71, 246, 7, 208, 107, 15, 206, 117, 14, 236, 217, 91, 241],
    [101, 62, 115, 238, 79, 110, 211, 165, 181, 66, 113, 54, 213, 137, 56, 253, 62, 237, 35, 211, 250, 107, 67, 140, 81, 102, 230, 229, 100, 90, 254, 252],
    [168, 50, 245, 176, 30, 124, 111, 46, 54, 67, 254, 251, 75, 142, 207, 181, 31, 13, 132, 210, 96, 94, 99, 185, 254, 57, 31, 77, 6, 146, 168, 73],
    [44, 134, 14, 165, 177, 202, 151, 251, 177, 232, 11, 51, 36, 53, 202, 6, 29, 73, 176, 100, 167, 253, 77, 103, 72, 214, 240, 181, 140, 95, 234, 200],
    [214, 129, 110, 222, 56, 107, 118, 38, 181, 225, 116, 224, 42, 76, 227, 87, 44, 9, 214, 236, 125, 197, 223, 70, 55, 63, 96, 159, 64, 148, 137, 158],
    [66, 134, 236, 147, 201, 111, 253, 37, 63, 36, 198, 241, 59, 45, 59, 178, 134, 81, 203, 175, 99, 225, 73, 198, 12, 57, 36, 71, 58, 83, 152, 248],
    [33, 141, 178, 49, 23, 212, 152, 99, 27, 252, 34, 150, 73, 154, 178, 126, 7, 44, 206, 244, 250, 234, 202, 99, 229, 162, 236, 204, 126, 34, 244, 172],
    [215, 156, 144, 117, 61, 199, 230, 121, 121, 139, 244, 48, 181, 73, 163, 30, 171, 82, 60, 5, 50, 55, 10, 80, 47, 156, 186, 129, 153, 49, 171, 59],
    [177, 19, 144, 39, 106, 190, 176, 53, 115, 185, 115, 71, 132, 191, 33, 9, 114, 207, 150, 56, 37, 152, 196, 193, 227, 32, 64, 211, 228, 18, 209, 29],
    [54, 97, 34, 163, 159, 136, 105, 231, 116, 125, 180, 143, 134, 66, 49, 177, 235, 211, 80, 81, 234, 229, 156, 95, 248, 188, 185, 84, 60, 202, 174, 201],
    [126, 216, 90, 49, 209, 134, 206, 237, 201, 43, 97, 29, 8, 146, 156, 15, 165, 240, 14, 93, 20, 74, 187, 6, 40, 35, 197, 103, 213, 202, 136, 203],
    [148, 197, 0, 200, 190, 231, 232, 205, 182, 222, 52, 193, 110, 100, 20, 196, 86, 205, 185, 192, 14, 15, 249, 46, 105, 241, 106, 16, 131, 4, 58, 25],
    [123, 184, 154, 98, 138, 2, 154, 22, 222, 172, 145, 125, 190, 14, 25, 130, 151, 202, 164, 234, 12, 241, 142, 185, 31, 122, 168, 149, 113, 178, 140, 28],
    [159, 174, 48, 84, 21, 54, 86, 132, 131, 138, 169, 129, 16, 40, 95, 15, 127, 75, 240, 245, 2, 129, 254, 92, 209, 90, 91, 201, 24, 57, 111, 206],
    [44, 21, 241, 49, 253, 126, 46, 68, 35, 10, 102, 105, 54, 126, 22, 116, 103, 42, 162, 152, 5, 113, 237, 160, 98, 205, 111, 80, 156, 59, 91, 141],
    [123, 148, 208, 255, 80, 208, 115, 134, 249, 116, 215, 240, 166, 214, 106, 59, 108, 80, 140, 48, 94, 76, 0, 178, 166, 21, 13, 208, 141, 193, 18, 157],
    [220, 223, 202, 140, 163, 192, 11, 149, 118, 245, 5, 36, 23, 143, 244, 239, 184, 229, 84, 139, 59, 178, 214, 184, 187, 133, 160, 33, 208, 66, 181, 24],
    [180, 188, 179, 142, 149, 188, 162, 248, 234, 146, 79, 171, 244, 245, 202, 103, 203, 232, 193, 180, 54, 27, 58, 101, 158, 131, 125, 243, 104, 162, 58, 188],
    [219, 237, 87, 131, 0, 187, 174, 27, 103, 65, 102, 123, 62, 91, 222, 245, 252, 107, 28, 77, 93, 205, 36, 41, 49, 206, 210, 11, 102, 123, 226, 92],
    [218, 161, 32, 11, 255, 230, 96, 187, 224, 180, 242, 26, 22, 192, 194, 185, 75, 134, 21, 87, 26, 108, 244, 79, 113, 176, 51, 156, 232, 22, 50, 141],
    [201, 216, 152, 16, 37, 86, 216, 169, 232, 19, 89, 131, 186, 78, 24, 185, 238, 161, 75, 158, 136, 36, 199, 253, 38, 222, 143, 67, 248, 168, 68, 92],
    [160, 212, 93, 14, 204, 62, 14, 69, 131, 142, 81, 94, 102, 73, 16, 126, 122, 54, 193, 165, 153, 161, 178, 81, 248, 23, 224, 191, 112, 237, 146, 11],
    [53, 240, 104, 132, 227, 187, 113, 177, 205, 44, 225, 236, 80, 193, 41, 37, 23, 134, 133, 118, 82, 106, 201, 255, 251, 79, 173, 125, 234, 13, 44, 68],
    [228, 203, 109, 223, 191, 126, 52, 136, 20, 65, 172, 177, 87, 76, 127, 43, 4, 101, 217, 205, 240, 103, 217, 152, 71, 30, 67, 73, 35, 53, 118, 136],
    [238, 11, 44, 147, 238, 34, 4, 121, 97, 52, 11, 212, 156, 187, 232, 224, 54, 69, 198, 199, 17, 33, 223, 17, 183, 143, 81, 188, 166, 36, 73, 196],
    [22, 163, 47, 53, 73, 34, 235, 41, 200, 140, 239, 143, 185, 70, 214, 34, 75, 223, 117, 245, 49, 147, 135, 14, 6, 106, 87, 19, 62, 214, 4, 92],
    [174, 206, 176, 199, 200, 250, 126, 20, 210, 63, 159, 179, 130, 116, 148, 158, 148, 133, 127, 221, 6, 120, 199, 237, 90, 114, 113, 228, 255, 121, 84, 45],
    [9, 122, 32, 251, 59, 89, 195, 104, 105, 78, 208, 61, 26, 196, 236, 227, 88, 126, 201, 214, 183, 118, 189, 58, 174, 229, 146, 119, 22, 6, 6, 178],
    [30, 219, 235, 25, 144, 58, 100, 110, 238, 123, 27, 35, 189, 126, 152, 241, 223, 163, 15, 145, 125, 73, 123, 31, 102, 97, 88, 41, 4, 76, 242, 102],
    [50, 150, 49, 39, 145, 157, 5, 92, 222, 176, 245, 43, 2, 57, 40, 220, 101, 199, 43, 192, 112, 195, 215, 131, 117, 47, 74, 200, 75, 81, 177, 230],
    [93, 225, 195, 128, 50, 227, 32, 99, 98, 213, 169, 198, 3, 64, 95, 110, 166, 255, 253, 60, 59, 94, 92, 173, 211, 224, 138, 127, 91, 222, 161, 217],
    [216, 183, 47, 255, 155, 214, 153, 195, 136, 243, 120, 177, 70, 87, 14, 76, 116, 126, 31, 23, 163, 15, 23, 242, 234, 60, 17, 137, 99, 86, 123, 91],
    [247, 198, 72, 132, 58, 70, 167, 152, 102, 71, 212, 165, 11, 144, 198, 104, 243, 118, 106, 70, 86, 61, 196, 235, 8, 50, 40, 67, 152, 93, 247, 82],
    [128, 28, 95, 146, 19, 230, 186, 115, 241, 117, 150, 167, 34, 63, 56, 12, 103, 237, 245, 160, 128, 171, 218, 94, 78, 208, 227, 222, 49, 212, 72, 82],
    [38, 169, 18, 200, 232, 193, 243, 224, 90, 219, 68, 152, 79, 19, 103, 230, 1, 173, 208, 50, 127, 93, 2, 158, 102, 60, 237, 75, 6, 63, 117, 243],
    [226, 75, 101, 146, 14, 244, 129, 28, 239, 153, 168, 86, 99, 251, 43, 158, 12, 14, 67, 22, 200, 177, 19, 35, 180, 89, 226, 180, 201, 126, 223, 115],
    [126, 161, 26, 67, 122, 62, 237, 179, 187, 23, 80, 156, 197, 207, 5, 82, 158, 176, 20, 26, 106, 201, 180, 249, 130, 67, 148, 61, 6, 94, 176, 13],
    [163, 75, 99, 12, 82, 146, 245, 27, 67, 221, 247, 77, 201, 42, 168, 131, 216, 0, 171, 151, 109, 158, 77, 158, 46, 62, 214, 137, 67, 26, 211, 86],
    [219, 161, 210, 20, 217, 151, 159, 25, 193, 102, 253, 36, 205, 186, 88, 184, 72, 78, 29, 103, 72, 213, 13, 36, 23, 100, 97, 30, 34, 138, 219, 132],
    [149, 224, 48, 253, 222, 50, 58, 244, 210, 182, 215, 16, 55, 244, 143, 63, 229, 140, 228, 180, 202, 141, 148, 145, 217, 207, 58, 144, 27, 17, 184, 70],
    [203, 82, 96, 89, 255, 162, 14, 250, 114, 157, 227, 20, 85, 198, 186, 59, 18, 212, 251, 211, 173, 121, 110, 42, 209, 248, 136, 57, 59, 237, 215, 168],
    [221, 240, 113, 93, 227, 210, 125, 117, 58, 172, 61, 105, 90, 99, 86, 14, 157, 64, 246, 101, 134, 83, 52, 16, 209, 92, 81, 54, 30, 43, 118, 41],
    [81, 18, 52, 153, 251, 56, 56, 103, 56, 89, 238, 64, 84, 254, 239, 86, 107, 171, 45, 146, 171, 27, 211, 142, 119, 48, 13, 106, 245, 141, 239, 222],
    [38, 69, 43, 178, 225, 128, 52, 243, 19, 48, 187, 185, 40, 1, 239, 50, 191, 172, 88, 222, 175, 244, 250, 44, 168, 235, 250, 213, 180, 31, 223, 241],
    [249, 73, 12, 24, 90, 129, 59, 86, 214, 117, 41, 204, 57, 75, 31, 191, 212, 59, 250, 213, 36, 39, 61, 7, 231, 211, 128, 233, 171, 158, 110, 255],
    [67, 223, 20, 86, 112, 159, 221, 48, 205, 210, 138, 173, 70, 24, 236, 139, 19, 176, 99, 165, 113, 87, 243, 186, 245, 90, 243, 141, 5, 32, 83, 201],
    [75, 220, 139, 160, 165, 78, 52, 19, 221, 237, 50, 42, 130, 79, 243, 125, 129, 249, 127, 135, 134, 45, 72, 185, 35, 120, 114, 124, 167, 95, 115, 68],
    [103, 216, 100, 158, 67, 62, 216, 162, 210, 111, 191, 27, 109, 239, 15, 219, 108, 205, 202, 215, 12, 152, 55, 20, 160, 118, 115, 50, 36, 227, 12, 213],
    [150, 63, 175, 20, 75, 162, 8, 119, 227, 124, 219, 43, 130, 241, 247, 42, 136, 230, 135, 233, 117, 21, 162, 188, 227, 81, 128, 60, 237, 19, 219, 225],
    [112, 78, 69, 177, 193, 18, 82, 170, 132, 238, 168, 206, 44, 154, 22, 144, 63, 158, 48, 2, 44, 202, 220, 174, 248, 186, 6, 184, 163, 210, 94, 52],
    [62, 36, 227, 218, 68, 230, 42, 24, 226, 208, 160, 90, 98, 42, 111, 141, 231, 117, 182, 245, 175, 138, 146, 217, 125, 170, 78, 42, 131, 148, 191, 151],
    [2, 238, 81, 211, 161, 196, 123, 111, 41, 182, 223, 70, 134, 46, 78, 152, 253, 233, 72, 86, 194, 151, 67, 133, 155, 71, 40, 9, 255, 189, 187, 230],
    [147, 108, 201, 84, 105, 150, 191, 213, 128, 129, 4, 205, 173, 224, 153, 80, 82, 217, 168, 63, 20, 120, 255, 247, 128, 120, 169, 71, 2, 22, 22, 37],
    [80, 84, 251, 198, 208, 143, 116, 100, 95, 8, 91, 79, 91, 37, 228, 119, 213, 238, 142, 245, 3, 84, 77, 112, 116, 86, 107, 36, 106, 107, 163, 185],
    [60, 134, 25, 214, 77, 122, 245, 192, 131, 45, 105, 134, 141, 101, 17, 156, 167, 104, 19, 92, 148, 135, 150, 123, 192, 159, 32, 82, 69, 254, 217, 160],
    [66, 42, 54, 155, 221, 131, 97, 31, 16, 236, 30, 112, 113, 243, 207, 105, 2, 127, 121, 36, 96, 143, 246, 128, 47, 85, 126, 216, 30, 9, 24, 120],
    [180, 34, 132, 162, 204, 54, 121, 249, 30, 115, 169, 137, 225, 8, 168, 85, 35, 89, 60, 66, 172, 238, 249, 42, 154, 171, 97, 18, 136, 73, 129, 154],
    [150, 80, 88, 57, 21, 126, 79, 9, 132, 37, 139, 137, 189, 169, 12, 54, 97, 191, 206, 133, 5, 211, 65, 32, 242, 152, 146, 54, 244, 197, 118, 162],
    [138, 121, 164, 249, 54, 133, 72, 174, 136, 225, 185, 236, 121, 195, 144, 199, 16, 136, 6, 18, 250, 88, 59, 212, 45, 66, 181, 146, 7, 41, 45, 222],
    [245, 186, 87, 238, 105, 217, 145, 129, 162, 23, 196, 234, 225, 113, 150, 182, 183, 14, 124, 129, 66, 72, 8, 72, 205, 82, 91, 239, 158, 42, 192, 175],
    [179, 247, 213, 246, 160, 139, 113, 20, 148, 115, 123, 61, 221, 241, 36, 19, 206, 187, 202, 185, 231, 250, 185, 158, 52, 183, 214, 161, 249, 180, 2, 237],
    [239, 156, 248, 124, 57, 37, 200, 251, 225, 148, 201, 50, 158, 111, 13, 58, 152, 121, 122, 35, 80, 101, 206, 26, 39, 103, 181, 20, 146, 59, 18, 68],
    [27, 108, 253, 204, 63, 106, 180, 8, 30, 193, 60, 140, 111, 80, 106, 244, 48, 128, 233, 20, 149, 106, 188, 7, 87, 246, 159, 47, 147, 187, 206, 26],
    [31, 65, 251, 237, 147, 130, 245, 44, 74, 3, 55, 195, 168, 0, 157, 71, 166, 73, 193, 45, 151, 55, 152, 235, 139, 153, 1, 101, 219, 124, 157, 241],
    [160, 204, 83, 133, 120, 75, 205, 61, 110, 39, 109, 147, 0, 50, 247, 55, 51, 242, 220, 9, 11, 186, 207, 43, 168, 122, 230, 8, 192, 145, 73, 22],
    [136, 181, 155, 102, 82, 76, 231, 49, 217, 179, 121, 54, 133, 171, 77, 212, 52, 0, 183, 114, 180, 138, 161, 81, 254, 23, 72, 238, 34, 53, 200, 70],
    [27, 34, 247, 203, 136, 160, 139, 199, 124, 109, 111, 144, 141, 77, 182, 227, 227, 45, 112, 165, 114, 164, 212, 78, 46, 190, 83, 28, 87, 192, 161, 195],
    [124, 255, 237, 122, 20, 176, 84, 121, 4, 217, 228, 235, 198, 103, 177, 20, 84, 130, 139, 4, 36, 119, 223, 182, 251, 164, 35, 4, 104, 110, 49, 25],
    [189, 170, 226, 143, 9, 226, 209, 107, 84, 215, 146, 89, 60, 144, 93, 33, 235, 35, 177, 185, 200, 62, 113, 139, 188, 214, 37, 155, 163, 42, 237, 192],
    [193, 52, 186, 31, 24, 244, 50, 26, 69, 7, 143, 133, 151, 74, 75, 32, 19, 244, 175, 164, 125, 92, 39, 102, 81, 118, 74, 1, 110, 220, 149, 19],
    [41, 44, 101, 131, 235, 232, 47, 238, 236, 237, 19, 168, 107, 219, 131, 138, 21, 175, 204, 91, 244, 127, 42, 207, 81, 81, 80, 126, 174, 3, 215, 124],
    [192, 68, 54, 101, 206, 53, 4, 65, 134, 36, 140, 170, 24, 194, 24, 129, 217, 152, 100, 33, 224, 147, 39, 49, 172, 233, 232, 47, 65, 76, 113, 62],
    [83, 211, 9, 143, 69, 149, 184, 76, 167, 66, 112, 140, 190, 124, 44, 56, 253, 103, 83, 73, 246, 252, 250, 236, 217, 229, 20, 125, 86, 254, 167, 41],
    [193, 38, 16, 156, 255, 102, 85, 23, 100, 162, 254, 109, 70, 101, 250, 154, 62, 252, 13, 124, 72, 38, 220, 91, 123, 233, 122, 107, 21, 169, 88, 146],
    [71, 55, 132, 60, 236, 231, 83, 144, 173, 78, 91, 188, 25, 203, 42, 15, 206, 69, 195, 26, 141, 215, 166, 132, 167, 154, 92, 216, 135, 40, 109, 131],
    [167, 75, 161, 251, 214, 191, 252, 46, 222, 140, 252, 123, 121, 143, 110, 145, 45, 101, 39, 7, 43, 23, 149, 187, 48, 146, 246, 141, 90, 168, 148, 68],
    [24, 201, 76, 70, 49, 63, 59, 156, 235, 239, 102, 178, 250, 239, 57, 210, 44, 72, 70, 97, 210, 38, 88, 111, 51, 174, 6, 52, 29, 35, 185, 31],
    [47, 17, 82, 41, 187, 247, 150, 179, 2, 46, 171, 77, 113, 111, 149, 128, 104, 41, 215, 156, 113, 30, 5, 12, 142, 249, 15, 100, 10, 243, 228, 22],
    [151, 28, 116, 116, 224, 158, 45, 9, 162, 142, 23, 88, 13, 51, 133, 88, 161, 2, 102, 67, 146, 164, 60, 227, 131, 60, 190, 123, 148, 205, 111, 22],
    [4, 11, 115, 236, 13, 99, 8, 199, 150, 194, 60, 160, 86, 233, 186, 101, 129, 246, 35, 64, 76, 182, 44, 13, 63, 142, 138, 7, 174, 117, 87, 13],
    [44, 146, 117, 104, 117, 113, 124, 156, 160, 107, 53, 64, 254, 17, 54, 199, 110, 151, 30, 132, 41, 99, 0, 213, 108, 178, 66, 79, 233, 89, 141, 169],
    [205, 25, 62, 249, 162, 85, 80, 133, 171, 67, 160, 18, 30, 225, 218, 102, 100, 249, 90, 109, 109, 204, 246, 205, 61, 231, 205, 169, 22, 32, 142, 140],
    [9, 18, 90, 252, 220, 144, 230, 90, 20, 94, 121, 109, 215, 128, 91, 181, 38, 54, 71, 131, 196, 142, 146, 76, 177, 166, 63, 147, 254, 168, 193, 57],
    [40, 179, 164, 196, 240, 226, 193, 226, 170, 224, 115, 133, 222, 114, 164, 90, 56, 53, 207, 226, 37, 23, 162, 86, 20, 222, 172, 126, 190, 9, 254, 33],
    [110, 152, 31, 195, 235, 177, 247, 179, 123, 16, 204, 237, 246, 240, 165, 113, 143, 158, 83, 138, 65, 49, 117, 218, 139, 158, 160, 178, 202, 220, 177, 4],
    [245, 140, 31, 136, 22, 129, 38, 205, 120, 247, 202, 50, 223, 166, 76, 91, 77, 58, 196, 123, 134, 102, 2, 42, 55, 222, 66, 63, 130, 88, 152, 0],
    [35, 206, 183, 127, 31, 227, 66, 166, 64, 163, 5, 149, 193, 89, 220, 105, 222, 96, 88, 172, 68, 135, 223, 97, 248, 110, 220, 202, 3, 66, 220, 117],
    [155, 171, 174, 238, 228, 49, 128, 119, 122, 9, 62, 111, 198, 47, 172, 248, 205, 36, 216, 116, 118, 83, 221, 203, 197, 35, 171, 170, 140, 105, 86, 1],
    [177, 128, 190, 142, 70, 190, 3, 189, 194, 31, 38, 220, 43, 136, 62, 99, 172, 218, 54, 35, 112, 64, 226, 155, 248, 183, 29, 18, 55, 85, 26, 85],
    [22, 159, 32, 0, 106, 75, 224, 176, 123, 221, 34, 80, 72, 212, 22, 44, 61, 66, 151, 121, 238, 50, 129, 236, 157, 7, 228, 145, 63, 32, 177, 18],
    [85, 60, 115, 107, 148, 189, 42, 36, 146, 212, 27, 158, 174, 108, 69, 254, 18, 146, 186, 223, 187, 220, 95, 147, 91, 115, 173, 84, 22, 193, 241, 90],
    [90, 83, 15, 219, 72, 59, 15, 81, 88, 123, 150, 18, 133, 209, 211, 236, 16, 59, 160, 78, 87, 191, 17, 114, 205, 197, 206, 45, 242, 164, 213, 60],
    [123, 241, 81, 153, 83, 192, 225, 6, 191, 93, 32, 60, 57, 216, 138, 199, 47, 155, 171, 140, 111, 48, 230, 140, 43, 27, 228, 2, 98, 30, 135, 63],
    [100, 156, 56, 199, 255, 68, 253, 192, 137, 99, 76, 198, 180, 134, 138, 252, 24, 245, 94, 228, 226, 154, 234, 99, 32, 145, 207, 160, 95, 34, 230, 32],
    [59, 147, 159, 4, 117, 44, 211, 113, 135, 145, 193, 33, 5, 189, 44, 187, 187, 101, 83, 15, 235, 173, 197, 24, 107, 12, 205, 141, 159, 16, 163, 148],
    [235, 176, 174, 95, 116, 31, 6, 211, 98, 167, 44, 204, 110, 78, 205, 69, 13, 151, 141, 17, 199, 167, 6, 227, 231, 8, 124, 152, 65, 119, 156, 34],
    [69, 216, 255, 174, 180, 172, 77, 31, 160, 218, 141, 62, 15, 246, 233, 175, 244, 32, 65, 67, 198, 68, 100, 52, 29, 66, 64, 255, 134, 165, 142, 45],
    [113, 37, 27, 214, 164, 177, 38, 43, 152, 248, 240, 77, 6, 221, 204, 206, 75, 40, 144, 214, 45, 25, 187, 175, 254, 48, 137, 34, 161, 51, 191, 114],
    [63, 92, 27, 58, 36, 165, 31, 65, 158, 66, 11, 254, 56, 147, 155, 195, 151, 21, 22, 0, 175, 76, 211, 87, 81, 208, 230, 84, 205, 153, 218, 99],
    [26, 100, 217, 72, 48, 61, 82, 232, 178, 96, 8, 4, 76, 86, 192, 41, 20, 132, 161, 96, 5, 129, 234, 68, 203, 15, 81, 183, 142, 34, 5, 173],
    [27, 239, 184, 32, 212, 227, 109, 187, 107, 243, 138, 248, 16, 73, 33, 207, 127, 67, 186, 191, 56, 239, 35, 115, 44, 6, 177, 130, 51, 159, 152, 86],
    [131, 188, 151, 151, 201, 171, 26, 155, 167, 133, 135, 195, 231, 50, 177, 38, 51, 119, 188, 13, 241, 188, 150, 254, 100, 176, 239, 180, 147, 6, 11, 243],
    [89, 128, 238, 3, 32, 237, 165, 195, 88, 198, 188, 26, 161, 16, 108, 102, 86, 183, 128, 100, 234, 102, 112, 122, 243, 193, 232, 188, 164, 127, 59, 89],
    [4, 201, 48, 2, 142, 239, 227, 79, 211, 107, 234, 193, 67, 46, 117, 144, 69, 198, 18, 172, 193, 3, 249, 142, 28, 59, 46, 250, 62, 211, 92, 223],
    [203, 1, 248, 228, 37, 14, 160, 234, 27, 146, 72, 226, 238, 212, 22, 255, 76, 173, 123, 166, 213, 162, 46, 147, 108, 194, 97, 2, 9, 145, 239, 120],
    [156, 30, 83, 45, 79, 213, 164, 6, 126, 86, 85, 222, 246, 145, 87, 190, 228, 191, 73, 170, 191, 4, 9, 152, 186, 7, 36, 94, 21, 101, 54, 60],
    [71, 93, 62, 199, 242, 16, 221, 57, 99, 210, 137, 115, 152, 162, 44, 185, 247, 175, 19, 166, 144, 135, 139, 237, 238, 146, 212, 228, 81, 245, 244, 171],
    [230, 108, 209, 117, 127, 207, 87, 211, 155, 157, 244, 243, 3, 101, 250, 151, 82, 120, 187, 235, 150, 0, 48, 61, 148, 169, 34, 251, 167, 86, 101, 218],
    [81, 18, 136, 33, 161, 30, 71, 215, 85, 167, 38, 217, 212, 162, 171, 42, 210, 143, 143, 143, 213, 63, 168, 167, 137, 213, 101, 167, 21, 10, 120, 243],
    [205, 137, 40, 56, 29, 155, 167, 191, 166, 28, 197, 5, 150, 128, 168, 108, 1, 50, 130, 179, 146, 107, 105, 82, 154, 155, 236, 214, 251, 246, 50, 48],
    [186, 193, 226, 66, 78, 29, 82, 41, 53, 205, 209, 79, 123, 151, 11, 232, 30, 131, 71, 110, 221, 3, 146, 190, 135, 193, 231, 164, 207, 148, 191, 174],
    [10, 206, 108, 37, 104, 66, 119, 116, 228, 62, 11, 90, 158, 147, 249, 145, 231, 212, 165, 8, 147, 59, 245, 22, 51, 194, 150, 61, 228, 174, 205, 162],
    [93, 199, 125, 188, 149, 107, 182, 47, 179, 70, 131, 239, 50, 212, 202, 71, 16, 234, 191, 251, 35, 217, 87, 142, 67, 115, 84, 85, 174, 7, 239, 169],
    [205, 36, 131, 160, 30, 35, 57, 106, 79, 230, 53, 215, 36, 57, 110, 63, 92, 50, 40, 118, 209, 231, 59, 247, 190, 231, 59, 220, 165, 170, 36, 54],
    [166, 164, 146, 33, 142, 34, 135, 249, 203, 133, 5, 126, 195, 205, 136, 249, 181, 209, 189, 55, 1, 217, 33, 134, 172, 38, 221, 38, 109, 205, 12, 106],
    [47, 117, 230, 209, 224, 80, 29, 9, 41, 207, 39, 4, 84, 123, 10, 19, 62, 90, 9, 167, 195, 41, 232, 48, 153, 217, 116, 55, 8, 69, 79, 109],
    [8, 104, 81, 53, 33, 247, 127, 170, 225, 207, 82, 0, 217, 255, 150, 3, 0, 127, 160, 78, 12, 174, 249, 248, 17, 131, 180, 77, 70, 203, 186, 134],
    [210, 191, 140, 73, 162, 173, 37, 190, 43, 108, 64, 50, 45, 3, 253, 85, 163, 141, 15, 96, 141, 92, 47, 136, 83, 193, 171, 136, 221, 180, 163, 124],
    [128, 19, 185, 243, 117, 67, 123, 62, 230, 224, 109, 190, 100, 178, 86, 235, 8, 183, 128, 163, 92, 172, 70, 12, 225, 174, 152, 178, 200, 76, 156, 230],
    [159, 101, 217, 215, 121, 29, 201, 226, 189, 122, 219, 25, 78, 73, 154, 241, 141, 63, 119, 210, 207, 23, 237, 87, 238, 114, 49, 60, 178, 112, 203, 61],
    [217, 220, 206, 185, 162, 202, 137, 211, 89, 124, 186, 198, 21, 63, 176, 246, 4, 52, 216, 92, 188, 15, 202, 130, 191, 74, 80, 35, 87, 125, 157, 17],
    [217, 126, 88, 171, 49, 117, 166, 197, 89, 99, 175, 246, 118, 246, 21, 195, 185, 222, 173, 185, 232, 3, 150, 238, 156, 225, 105, 141, 62, 108, 116, 15],
    [24, 36, 223, 52, 255, 102, 85, 51, 208, 149, 155, 19, 201, 37, 146, 158, 58, 195, 208, 32, 192, 128, 222, 189, 201, 219, 219, 155, 75, 143, 159, 15],
    [106, 68, 151, 236, 115, 118, 234, 47, 164, 255, 234, 164, 119, 115, 158, 126, 15, 138, 185, 74, 199, 142, 163, 1, 215, 42, 134, 66, 75, 41, 124, 255],
    [116, 119, 135, 132, 237, 118, 23, 55, 57, 180, 151, 7, 88, 165, 7, 37, 198, 57, 227, 184, 255, 15, 90, 116, 63, 253, 132, 32, 150, 151, 245, 194],
    [181, 241, 137, 221, 21, 142, 159, 91, 29, 253, 54, 232, 57, 129, 12, 81, 210, 160, 42, 236, 220, 34, 217, 142, 141, 171, 212, 10, 173, 60, 11, 30],
    [122, 32, 159, 212, 191, 80, 0, 231, 90, 60, 195, 19, 194, 13, 217, 95, 169, 188, 7, 3, 7, 21, 35, 24, 224, 85, 153, 242, 11, 211, 105, 235],
    [156, 121, 87, 156, 96, 23, 85, 134, 26, 223, 81, 120, 172, 148, 43, 65, 205, 254, 48, 149, 135, 67, 228, 213, 134, 29, 28, 157, 132, 32, 61, 204],
    [33, 230, 113, 165, 36, 7, 244, 4, 216, 165, 129, 192, 255, 3, 72, 96, 254, 204, 151, 116, 248, 254, 188, 111, 222, 197, 37, 6, 116, 173, 244, 36],
    [177, 87, 23, 172, 2, 8, 113, 52, 114, 62, 106, 71, 79, 212, 127, 93, 196, 134, 27, 186, 200, 235, 205, 202, 131, 64, 44, 9, 87, 139, 60, 34],
    [208, 23, 184, 97, 104, 185, 217, 121, 80, 187, 246, 122, 88, 10, 166, 172, 183, 96, 211, 82, 72, 97, 175, 223, 83, 62, 123, 119, 191, 60, 27, 125],
    [183, 195, 230, 91, 50, 248, 105, 29, 232, 61, 179, 253, 60, 230, 34, 38, 201, 92, 25, 129, 60, 39, 175, 251, 199, 113, 223, 87, 62, 136, 70, 217],
    [154, 219, 126, 224, 53, 98, 251, 116, 63, 221, 68, 168, 71, 121, 7, 33, 222, 67, 79, 67, 231, 241, 131, 242, 221, 171, 105, 238, 156, 126, 45, 51],
    [20, 222, 96, 135, 100, 26, 141, 171, 209, 196, 69, 113, 183, 175, 72, 245, 117, 0, 31, 131, 48, 230, 254, 11, 66, 143, 187, 39, 21, 204, 70, 23],
    [95, 153, 120, 131, 129, 17, 54, 152, 35, 22, 84, 217, 128, 252, 115, 141, 142, 25, 17, 198, 163, 13, 232, 203, 51, 162, 158, 247, 193, 237, 195, 25],
    [33, 139, 255, 154, 238, 107, 213, 38, 161, 35, 50, 182, 229, 84, 239, 49, 159, 201, 81, 69, 78, 155, 161, 244, 149, 56, 141, 96, 103, 57, 35, 85],
    [162, 132, 12, 38, 254, 168, 40, 141, 135, 109, 196, 48, 64, 196, 76, 254, 225, 0, 162, 154, 240, 54, 125, 119, 178, 14, 178, 204, 8, 106, 180, 126],
    [119, 102, 57, 200, 150, 246, 238, 234, 90, 36, 101, 99, 122, 202, 241, 154, 254, 17, 216, 230, 251, 97, 38, 226, 137, 3, 155, 111, 88, 151, 31, 200],
    [240, 166, 88, 210, 6, 94, 184, 90, 8, 198, 246, 52, 200, 76, 11, 23, 101, 221, 114, 111, 222, 78, 54, 123, 122, 236, 150, 173, 49, 101, 66, 4],
    [30, 211, 253, 107, 192, 40, 58, 162, 193, 141, 10, 54, 194, 71, 230, 58, 33, 232, 0, 248, 168, 209, 149, 64, 98, 184, 69, 85, 155, 101, 223, 123],
    [197, 82, 6, 178, 117, 149, 216, 188, 213, 2, 246, 103, 172, 132, 192, 207, 251, 146, 167, 204, 246, 82, 114, 102, 236, 26, 104, 228, 218, 229, 70, 18],
    [200, 224, 247, 238, 191, 214, 200, 124, 222, 134, 208, 79, 134, 217, 243, 176, 227, 89, 221, 4, 72, 255, 111, 60, 192, 102, 6, 234, 148, 167, 56, 123],
    [141, 165, 21, 218, 157, 26, 221, 63, 38, 110, 245, 63, 35, 159, 104, 5, 210, 102, 107, 47, 226, 142, 250, 112, 201, 202, 172, 183, 8, 14, 181, 44],
    [231, 213, 25, 236, 223, 44, 111, 198, 72, 158, 212, 183, 44, 24, 155, 27, 134, 218, 139, 214, 80, 207, 122, 14, 141, 106, 98, 181, 12, 211, 141, 95],
    [164, 165, 70, 105, 136, 22, 186, 50, 224, 195, 77, 200, 102, 221, 225, 182, 217, 54, 6, 66, 194, 193, 108, 150, 105, 172, 207, 150, 127, 130, 90, 22],
    [86, 127, 151, 176, 31, 158, 146, 252, 213, 85, 48, 105, 170, 232, 53, 36, 133, 148, 133, 56, 194, 228, 245, 35, 205, 115, 113, 42, 244, 155, 121, 67],
    [183, 94, 120, 44, 200, 51, 190, 20, 76, 253, 22, 21, 52, 128, 61, 19, 85, 216, 140, 221, 205, 213, 149, 78, 41, 36, 107, 40, 48, 112, 17, 87],
    [28, 55, 47, 8, 43, 209, 101, 37, 226, 63, 73, 150, 47, 7, 194, 66, 210, 47, 252, 36, 219, 250, 114, 226, 249, 85, 62, 247, 198, 0, 86, 114],
    [16, 85, 197, 147, 56, 83, 21, 238, 141, 12, 152, 37, 169, 239, 214, 153, 239, 187, 40, 180, 176, 57, 63, 32, 148, 57, 56, 37, 12, 80, 211, 163],
    [183, 29, 220, 224, 50, 12, 193, 158, 110, 116, 244, 193, 111, 240, 115, 44, 169, 30, 116, 181, 254, 232, 64, 246, 214, 163, 63, 162, 25, 46, 187, 105],
    [32, 160, 132, 32, 84, 125, 87, 52, 77, 130, 62, 127, 54, 223, 68, 246, 14, 47, 156, 223, 77, 71, 66, 12, 2, 195, 217, 234, 111, 135, 114, 178],
    [200, 67, 38, 1, 185, 120, 104, 175, 216, 175, 170, 246, 184, 120, 38, 103, 103, 115, 229, 245, 248, 193, 131, 101, 45, 196, 20, 101, 185, 106, 254, 204],
    [77, 2, 150, 97, 139, 201, 7, 99, 196, 48, 172, 156, 152, 81, 28, 196, 71, 202, 45, 173, 155, 210, 116, 82, 252, 57, 81, 44, 200, 31, 78, 44],
    [93, 246, 251, 24, 48, 12, 101, 178, 150, 185, 225, 246, 70, 68, 33, 138, 9, 96, 34, 61, 52, 128, 208, 224, 139, 240, 15, 206, 65, 39, 228, 160],
    [216, 103, 124, 234, 244, 102, 227, 102, 1, 77, 95, 62, 158, 229, 219, 23, 8, 98, 97, 191, 147, 70, 24, 52, 247, 58, 181, 94, 244, 204, 57, 140],
    [101, 190, 20, 219, 159, 153, 208, 18, 142, 83, 21, 77, 147, 53, 230, 18, 196, 108, 41, 155, 77, 47, 222, 181, 155, 11, 229, 29, 100, 105, 73, 149],
    [50, 240, 86, 105, 133, 165, 241, 97, 90, 181, 111, 2, 210, 182, 118, 229, 21, 242, 13, 34, 168, 64, 150, 101, 97, 128, 185, 190, 212, 228, 105, 199],
    [126, 30, 27, 122, 172, 199, 200, 18, 36, 157, 255, 15, 3, 176, 254, 48, 193, 82, 67, 137, 201, 137, 145, 188, 223, 72, 73, 80, 4, 166, 118, 211],
    [61, 158, 2, 52, 165, 28, 83, 1, 4, 135, 28, 63, 236, 5, 136, 99, 177, 137, 205, 158, 179, 109, 223, 64, 26, 115, 247, 57, 164, 147, 208, 107],
    [138, 53, 56, 0, 92, 118, 181, 180, 129, 75, 43, 220, 50, 206, 107, 110, 239, 211, 30, 237, 9, 129, 36, 56, 255, 245, 215, 161, 231, 149, 56, 80],
    [114, 233, 223, 153, 23, 214, 75, 198, 234, 162, 3, 232, 39, 54, 124, 186, 254, 86, 206, 49, 165, 214, 196, 123, 248, 211, 208, 26, 237, 9, 96, 154],
    [9, 19, 208, 55, 117, 152, 222, 106, 92, 87, 53, 181, 10, 160, 12, 96, 152, 113, 134, 45, 141, 39, 101, 21, 32, 153, 230, 242, 235, 121, 172, 50],
    [171, 9, 116, 124, 127, 57, 22, 250, 141, 33, 172, 111, 254, 46, 103, 125, 59, 26, 248, 107, 53, 73, 186, 83, 248, 119, 91, 217, 247, 210, 94, 248],
    [20, 234, 8, 108, 116, 67, 3, 37, 174, 114, 238, 210, 141, 227, 248, 5, 58, 35, 11, 236, 36, 54, 160, 15, 141, 91, 216, 203, 165, 208, 247, 242],
    [118, 0, 14, 195, 195, 216, 48, 118, 13, 253, 31, 141, 52, 254, 158, 185, 39, 201, 159, 26, 208, 168, 22, 78, 87, 0, 93, 83, 159, 62, 39, 106],
    [17, 152, 191, 127, 104, 129, 50, 121, 126, 11, 4, 4, 119, 239, 81, 144, 154, 130, 107, 181, 19, 147, 35, 204, 198, 123, 124, 84, 175, 218, 115, 175],
    [201, 28, 110, 86, 17, 91, 134, 85, 33, 198, 252, 215, 59, 119, 118, 46, 8, 49, 52, 189, 92, 174, 127, 29, 197, 43, 243, 139, 132, 162, 117, 209],
    [187, 237, 139, 65, 111, 73, 1, 54, 5, 234, 4, 251, 127, 73, 146, 246, 255, 105, 83, 53, 176, 247, 25, 163, 194, 38, 214, 86, 61, 207, 113, 207],
    [205, 202, 92, 208, 125, 123, 225, 94, 249, 18, 27, 162, 43, 80, 178, 121, 187, 65, 153, 17, 105, 236, 63, 105, 93, 133, 129, 224, 31, 229, 94, 122],
    [70, 181, 25, 168, 50, 89, 188, 53, 239, 119, 99, 15, 43, 173, 250, 135, 144, 181, 180, 106, 236, 124, 104, 122, 26, 148, 202, 222, 10, 58, 23, 238],
    [230, 78, 3, 104, 218, 46, 91, 230, 111, 128, 77, 88, 4, 193, 125, 244, 68, 150, 196, 5, 3, 237, 219, 127, 101, 158, 4, 191, 69, 53, 152, 64],
    [168, 54, 14, 125, 45, 201, 51, 219, 124, 184, 88, 28, 56, 52, 44, 228, 173, 32, 247, 173, 39, 193, 12, 19, 163, 60, 194, 53, 149, 128, 158, 183],
    [186, 9, 244, 79, 57, 133, 135, 54, 114, 73, 221, 90, 95, 104, 146, 202, 28, 172, 116, 170, 85, 72, 31, 225, 220, 78, 219, 161, 49, 218, 55, 202],
    [207, 184, 208, 123, 97, 22, 3, 160, 223, 59, 68, 144, 231, 233, 183, 148, 85, 154, 250, 96, 223, 26, 98, 203, 161, 153, 143, 107, 86, 10, 248, 61],
    [211, 197, 62, 37, 102, 132, 15, 46, 41, 164, 216, 171, 16, 104, 166, 65, 12, 50, 166, 46, 110, 105, 110, 106, 186, 103, 103, 87, 173, 175, 134, 24],
    [48, 241, 229, 251, 75, 251, 188, 197, 223, 108, 26, 111, 143, 81, 200, 55, 12, 112, 31, 87, 142, 135, 196, 56, 74, 70, 165, 245, 4, 112, 128, 158],
    [58, 143, 97, 72, 89, 22, 162, 240, 95, 226, 52, 24, 154, 188, 80, 49, 81, 4, 53, 120, 29, 146, 2, 43, 28, 117, 231, 147, 161, 100, 72, 54],
    [25, 75, 205, 239, 75, 242, 102, 239, 144, 10, 199, 220, 184, 109, 63, 129, 237, 74, 201, 246, 87, 76, 0, 43, 235, 95, 66, 211, 151, 111, 53, 168],
    [136, 211, 102, 84, 39, 88, 129, 255, 192, 37, 39, 193, 62, 237, 158, 140, 19, 4, 34, 11, 21, 223, 209, 35, 151, 27, 30, 32, 236, 188, 157, 97],
    [110, 206, 50, 27, 115, 86, 101, 6, 54, 97, 141, 30, 168, 133, 100, 9, 48, 35, 53, 134, 37, 125, 235, 47, 23, 212, 225, 128, 5, 130, 217, 148],
    [247, 249, 104, 127, 129, 159, 8, 72, 89, 135, 158, 87, 52, 192, 43, 71, 27, 203, 186, 148, 35, 176, 198, 193, 159, 206, 27, 54, 191, 10, 238, 59],
    [206, 30, 144, 14, 93, 94, 252, 153, 125, 96, 205, 2, 104, 156, 146, 125, 1, 124, 135, 23, 192, 129, 224, 84, 140, 178, 4, 130, 29, 219, 134, 15],
    [124, 185, 250, 114, 56, 30, 65, 58, 205, 228, 20, 177, 54, 6, 213, 64, 89, 134, 197, 239, 153, 234, 142, 117, 150, 108, 104, 11, 183, 145, 123, 25],
    [221, 227, 243, 40, 57, 33, 251, 99, 45, 181, 183, 213, 191, 181, 202, 147, 25, 26, 64, 135, 12, 99, 213, 155, 137, 147, 187, 13, 71, 167, 253, 219],
    [163, 160, 109, 196, 59, 182, 243, 73, 246, 118, 186, 63, 42, 176, 226, 91, 213, 62, 124, 136, 66, 109, 80, 89, 174, 237, 229, 216, 50, 38, 142, 125],
    [40, 255, 44, 26, 67, 200, 103, 169, 172, 210, 55, 36, 115, 22, 240, 244, 34, 15, 215, 40, 36, 10, 53, 8, 39, 195, 67, 235, 209, 79, 146, 218],
    [109, 85, 252, 232, 85, 134, 232, 158, 162, 82, 203, 52, 26, 74, 66, 24, 109, 203, 63, 150, 98, 249, 61, 17, 236, 250, 110, 213, 161, 166, 98, 105],
    [113, 196, 155, 12, 189, 83, 101, 119, 176, 86, 204, 73, 196, 148, 170, 65, 4, 203, 237, 124, 93, 68, 149, 16, 95, 207, 32, 247, 85, 177, 215, 133],
    [101, 13, 114, 180, 253, 64, 34, 227, 53, 91, 115, 246, 104, 112, 125, 197, 206, 97, 86, 37, 132, 86, 202, 100, 164, 80, 83, 205, 136, 50, 128, 16],
    [7, 224, 185, 135, 221, 6, 54, 212, 18, 177, 244, 80, 184, 56, 176, 11, 24, 143, 103, 62, 218, 16, 130, 188, 249, 169, 203, 24, 152, 247, 56, 208],
    [44, 244, 120, 232, 44, 90, 134, 7, 226, 160, 192, 50, 14, 162, 137, 254, 146, 53, 137, 116, 208, 245, 68, 45, 103, 124, 97, 166, 23, 214, 63, 160],
    [143, 116, 89, 187, 97, 120, 126, 105, 43, 72, 183, 18, 223, 84, 245, 25, 3, 63, 171, 102, 207, 230, 42, 42, 128, 77, 249, 215, 185, 167, 44, 24],
    [31, 146, 10, 43, 77, 118, 243, 32, 232, 56, 142, 203, 36, 12, 178, 121, 9, 207, 158, 44, 119, 23, 189, 86, 162, 29, 42, 33, 41, 232, 163, 248],
    [171, 162, 16, 14, 140, 54, 216, 214, 170, 6, 80, 163, 41, 76, 95, 235, 188, 73, 68, 18, 100, 208, 152, 171, 44, 87, 124, 174, 177, 60, 92, 99],
    [33, 202, 128, 206, 47, 170, 123, 135, 125, 110, 117, 26, 115, 111, 110, 49, 65, 0, 144, 127, 188, 77, 6, 26, 25, 10, 5, 148, 194, 88, 122, 19],
    [113, 50, 105, 148, 97, 153, 7, 179, 233, 21, 139, 21, 183, 218, 183, 129, 253, 10, 115, 41, 200, 60, 14, 24, 33, 13, 214, 188, 186, 7, 131, 99],
    [114, 195, 45, 172, 81, 254, 164, 180, 215, 43, 91, 141, 148, 175, 158, 37, 6, 163, 66, 60, 25, 223, 253, 185, 76, 183, 23, 85, 231, 115, 151, 14],
    [232, 137, 147, 115, 138, 124, 50, 255, 177, 177, 68, 62, 42, 169, 11, 84, 148, 131, 134, 204, 21, 243, 91, 42, 189, 166, 144, 202, 97, 26, 2, 126],
    [95, 46, 177, 236, 15, 215, 147, 118, 196, 138, 252, 156, 21, 209, 152, 100, 148, 32, 95, 105, 8, 54, 67, 185, 214, 154, 5, 133, 244, 251, 220, 95],
    [63, 186, 244, 156, 65, 38, 1, 67, 105, 139, 72, 116, 192, 134, 35, 99, 105, 66, 118, 250, 208, 18, 53, 174, 92, 191, 48, 133, 62, 135, 169, 71],
    [24, 10, 127, 11, 161, 69, 169, 191, 64, 37, 147, 32, 59, 91, 1, 9, 254, 80, 242, 113, 190, 229, 32, 206, 29, 73, 198, 97, 42, 167, 30, 164],
    [28, 110, 129, 202, 249, 114, 37, 239, 172, 30, 224, 68, 55, 27, 99, 200, 171, 18, 91, 88, 131, 190, 112, 86, 175, 246, 245, 64, 5, 168, 27, 150],
    [142, 128, 11, 96, 128, 207, 145, 109, 114, 114, 138, 95, 217, 164, 209, 206, 129, 121, 129, 245, 99, 165, 159, 117, 41, 80, 209, 243, 73, 36, 107, 151],
    [24, 86, 210, 180, 42, 83, 121, 2, 161, 150, 146, 250, 184, 160, 13, 97, 91, 227, 120, 86, 218, 71, 185, 198, 38, 68, 214, 58, 184, 164, 220, 127],
    [229, 243, 182, 220, 184, 83, 86, 113, 16, 20, 111, 71, 63, 91, 70, 56, 141, 185, 54, 28, 161, 8, 195, 94, 137, 15, 114, 6, 183, 128, 195, 161],
    [24, 248, 172, 223, 64, 3, 181, 1, 233, 121, 50, 139, 130, 17, 159, 212, 77, 167, 15, 90, 247, 190, 72, 138, 103, 130, 163, 110, 170, 48, 7, 48],
    [2, 82, 18, 34, 140, 3, 11, 54, 102, 246, 6, 241, 70, 15, 229, 78, 153, 210, 88, 17, 205, 103, 50, 82, 15, 126, 11, 158, 33, 33, 101, 175],
    [53, 216, 55, 77, 8, 27, 11, 203, 83, 83, 230, 108, 197, 244, 85, 71, 140, 182, 239, 227, 72, 199, 98, 139, 184, 167, 224, 205, 11, 201, 195, 177],
    [88, 75, 31, 99, 234, 89, 22, 65, 51, 49, 113, 65, 249, 99, 116, 5, 197, 11, 161, 175, 5, 234, 219, 64, 74, 119, 29, 138, 83, 194, 97, 250],
    [74, 86, 117, 30, 50, 22, 134, 115, 126, 120, 56, 133, 82, 139, 26, 150, 200, 200, 83, 79, 144, 189, 248, 137, 64, 104, 8, 83, 249, 79, 95, 209],
    [121, 131, 239, 27, 152, 156, 108, 45, 216, 117, 111, 80, 132, 41, 185, 158, 54, 41, 96, 160, 50, 126, 233, 54, 217, 105, 243, 219, 62, 248, 214, 248],
    [187, 112, 213, 36, 92, 120, 191, 175, 253, 166, 62, 32, 164, 165, 250, 79, 123, 151, 172, 32, 200, 104, 147, 178, 80, 80, 2, 193, 148, 107, 255, 96],
    [21, 133, 253, 50, 51, 18, 217, 14, 24, 36, 178, 189, 169, 36, 145, 212, 82, 47, 189, 146, 109, 135, 115, 170, 50, 226, 130, 104, 221, 88, 62, 244],
    [156, 236, 74, 128, 231, 236, 144, 116, 105, 187, 59, 20, 168, 135, 118, 238, 159, 243, 202, 88, 157, 126, 137, 156, 182, 44, 169, 197, 221, 183, 229, 145],
    [119, 243, 211, 130, 190, 131, 33, 62, 112, 240, 138, 192, 72, 57, 210, 209, 107, 128, 155, 142, 15, 245, 209, 253, 184, 245, 162, 118, 148, 204, 6, 170],
    [223, 37, 210, 68, 1, 26, 4, 149, 41, 195, 4, 182, 126, 31, 116, 85, 212, 191, 80, 102, 109, 44, 6, 79, 86, 180, 247, 153, 54, 116, 208, 54],
    [42, 64, 179, 220, 41, 201, 52, 98, 209, 83, 51, 66, 76, 221, 220, 210, 131, 127, 55, 120, 185, 69, 251, 223, 103, 88, 243, 103, 95, 126, 137, 78],
    [174, 27, 245, 120, 227, 47, 198, 23, 23, 202, 74, 180, 183, 83, 18, 44, 93, 178, 17, 143, 141, 70, 154, 42, 16, 249, 104, 145, 61, 220, 68, 174],
    [144, 216, 107, 210, 89, 194, 17, 130, 216, 110, 167, 91, 157, 255, 28, 164, 56, 7, 112, 33, 207, 239, 179, 205, 104, 54, 152, 167, 40, 62, 213, 125],
    [90, 32, 117, 198, 146, 134, 72, 8, 206, 59, 36, 164, 215, 204, 70, 228, 182, 107, 29, 240, 43, 201, 193, 39, 109, 28, 207, 251, 132, 94, 227, 205],
    [156, 228, 3, 146, 93, 94, 190, 48, 80, 228, 157, 53, 204, 181, 158, 57, 151, 169, 178, 91, 121, 37, 243, 106, 42, 117, 111, 147, 244, 59, 229, 10],
    [103, 125, 59, 209, 181, 52, 252, 110, 173, 159, 252, 192, 222, 32, 163, 12, 19, 87, 30, 6, 12, 136, 162, 98, 107, 180, 237, 181, 3, 61, 37, 3],
    [241, 246, 101, 6, 167, 242, 209, 23, 9, 222, 179, 162, 207, 136, 176, 255, 136, 211, 240, 47, 229, 181, 3, 170, 16, 16, 103, 56, 242, 179, 212, 117],
    [161, 185, 3, 109, 235, 4, 176, 105, 143, 147, 228, 224, 177, 69, 179, 198, 244, 139, 62, 227, 80, 147, 39, 217, 96, 221, 38, 196, 69, 246, 106, 4],
    [62, 147, 177, 34, 14, 223, 191, 67, 127, 187, 200, 128, 165, 143, 107, 100, 2, 190, 196, 95, 153, 252, 134, 11, 22, 177, 147, 172, 245, 142, 84, 91],
    [247, 132, 130, 29, 236, 180, 210, 214, 73, 17, 195, 162, 179, 39, 88, 6, 235, 38, 1, 147, 150, 248, 21, 253, 91, 132, 101, 124, 15, 137, 131, 71],
    [43, 3, 180, 44, 130, 199, 26, 246, 228, 86, 182, 127, 251, 179, 188, 73, 122, 147, 203, 101, 149, 107, 151, 119, 50, 227, 35, 253, 44, 210, 141, 240],
    [138, 78, 240, 46, 123, 221, 153, 18, 122, 26, 110, 92, 196, 245, 69, 56, 14, 58, 143, 183, 89, 250, 197, 242, 94, 127, 248, 94, 36, 103, 143, 112],
    [81, 24, 63, 29, 145, 196, 216, 3, 237, 38, 164, 7, 204, 102, 29, 223, 144, 220, 31, 205, 239, 142, 111, 96, 67, 252, 203, 172, 77, 226, 171, 42],
    [64, 14, 249, 134, 49, 83, 114, 118, 159, 145, 186, 98, 55, 89, 113, 243, 115, 67, 120, 173, 13, 164, 165, 146, 180, 238, 66, 174, 158, 208, 95, 54],
    [217, 139, 83, 26, 176, 232, 72, 126, 34, 138, 30, 0, 245, 57, 21, 24, 178, 145, 209, 139, 10, 233, 48, 62, 26, 156, 155, 191, 53, 63, 62, 159],
    [13, 80, 105, 11, 154, 28, 193, 173, 9, 96, 255, 127, 247, 40, 143, 50, 146, 200, 194, 219, 39, 73, 122, 254, 61, 141, 37, 82, 255, 44, 158, 146],
    [186, 43, 144, 53, 245, 176, 239, 81, 219, 76, 244, 237, 174, 178, 179, 221, 119, 197, 182, 183, 138, 134, 113, 94, 226, 68, 214, 188, 0, 193, 98, 153],
    [39, 27, 174, 101, 224, 22, 22, 150, 136, 6, 176, 12, 53, 88, 115, 28, 55, 254, 38, 110, 103, 100, 77, 150, 189, 2, 4, 163, 50, 125, 212, 237],
    [219, 67, 79, 220, 216, 126, 186, 7, 148, 245, 195, 7, 115, 219, 107, 196, 194, 107, 129, 189, 174, 235, 13, 135, 182, 148, 75, 70, 204, 206, 22, 14],
    [190, 121, 119, 155, 78, 192, 96, 76, 140, 138, 93, 120, 31, 145, 185, 189, 190, 6, 30, 128, 44, 195, 68, 193, 79, 253, 199, 66, 24, 26, 31, 167],
    [89, 53, 146, 71, 192, 133, 79, 45, 247, 189, 60, 239, 129, 200, 122, 160, 243, 71, 233, 116, 62, 89, 231, 56, 137, 111, 40, 76, 223, 224, 11, 101],
    [204, 97, 17, 79, 128, 217, 150, 57, 188, 244, 50, 234, 48, 207, 119, 103, 167, 167, 202, 53, 40, 122, 36, 233, 143, 245, 229, 15, 213, 20, 63, 158],
    [176, 64, 244, 16, 70, 120, 251, 104, 226, 74, 237, 112, 160, 150, 44, 94, 199, 236, 30, 88, 114, 46, 133, 131, 81, 108, 198, 35, 208, 187, 137, 200],
    [65, 75, 42, 84, 200, 91, 207, 130, 157, 191, 170, 77, 39, 193, 60, 5, 183, 18, 4, 42, 231, 222, 84, 234, 24, 94, 93, 253, 194, 102, 65, 3],
    [139, 250, 20, 126, 188, 107, 166, 223, 180, 54, 53, 202, 155, 77, 157, 54, 34, 25, 52, 238, 249, 155, 255, 12, 191, 213, 18, 98, 242, 123, 244, 177],
    [159, 59, 24, 202, 215, 108, 220, 66, 17, 99, 247, 253, 250, 233, 40, 92, 16, 154, 29, 225, 133, 115, 246, 71, 52, 251, 114, 11, 33, 9, 203, 185],
    [192, 142, 241, 96, 94, 115, 232, 47, 228, 134, 189, 135, 165, 200, 36, 180, 67, 45, 211, 191, 95, 179, 45, 89, 192, 71, 168, 126, 102, 186, 59, 243],
    [203, 120, 86, 40, 182, 22, 125, 56, 34, 28, 235, 163, 117, 45, 141, 88, 30, 56, 171, 148, 248, 185, 186, 104, 182, 50, 208, 238, 174, 62, 214, 183],
    [209, 252, 24, 227, 219, 103, 67, 182, 176, 36, 117, 228, 176, 219, 95, 41, 27, 78, 36, 94, 17, 227, 255, 96, 49, 101, 51, 248, 220, 175, 21, 39],
    [185, 10, 131, 60, 102, 21, 222, 7, 1, 102, 46, 84, 104, 95, 150, 253, 88, 240, 60, 215, 7, 170, 168, 238, 124, 146, 198, 63, 8, 182, 175, 63],
    [21, 64, 57, 142, 144, 28, 165, 42, 21, 255, 22, 58, 54, 87, 94, 38, 139, 4, 209, 0, 43, 145, 99, 238, 103, 99, 255, 147, 243, 238, 233, 6],
    [28, 125, 9, 17, 208, 154, 31, 32, 249, 215, 123, 60, 22, 7, 228, 221, 61, 119, 210, 238, 72, 226, 213, 176, 107, 202, 244, 125, 181, 244, 200, 116],
    [162, 120, 218, 225, 48, 142, 222, 153, 221, 162, 10, 26, 72, 174, 9, 234, 173, 4, 28, 76, 175, 52, 186, 195, 110, 51, 191, 117, 128, 228, 72, 184],
    [151, 99, 3, 40, 116, 160, 195, 134, 19, 174, 62, 110, 144, 30, 132, 118, 81, 57, 132, 119, 53, 130, 119, 219, 83, 5, 201, 222, 251, 126, 0, 175],
    [221, 211, 119, 114, 99, 69, 155, 25, 36, 121, 216, 38, 51, 101, 219, 28, 43, 210, 83, 31, 242, 216, 203, 250, 143, 215, 238, 215, 25, 43, 16, 212],
    [7, 253, 18, 127, 9, 161, 113, 61, 233, 116, 202, 1, 48, 101, 83, 229, 153, 133, 228, 87, 175, 240, 227, 227, 251, 198, 210, 45, 162, 146, 82, 88],
    [110, 30, 152, 182, 92, 109, 165, 102, 197, 15, 121, 74, 145, 25, 42, 74, 96, 77, 202, 67, 136, 234, 163, 13, 186, 73, 98, 15, 121, 156, 217, 209],
    [187, 227, 34, 181, 17, 222, 215, 120, 100, 0, 166, 19, 94, 54, 117, 217, 150, 52, 248, 138, 42, 147, 47, 219, 253, 189, 200, 177, 151, 50, 103, 142],
    [187, 251, 142, 205, 104, 198, 9, 41, 206, 63, 29, 25, 122, 246, 59, 22, 57, 171, 67, 156, 29, 189, 122, 75, 202, 209, 102, 47, 50, 157, 37, 67],
    [173, 63, 185, 30, 51, 161, 215, 81, 165, 189, 108, 40, 155, 205, 105, 117, 25, 4, 4, 34, 179, 82, 79, 5, 113, 185, 69, 65, 123, 42, 37, 90],
    [250, 118, 3, 140, 218, 158, 210, 92, 223, 98, 204, 74, 249, 109, 136, 232, 199, 164, 102, 219, 51, 181, 107, 246, 236, 219, 28, 168, 169, 41, 170, 35],
    [55, 91, 127, 143, 0, 172, 237, 119, 100, 24, 120, 219, 237, 180, 9, 223, 81, 49, 118, 90, 202, 26, 181, 21, 82, 253, 155, 243, 236, 77, 102, 191],
    [23, 100, 53, 191, 144, 128, 17, 210, 81, 100, 252, 90, 14, 154, 148, 153, 233, 51, 170, 91, 217, 121, 31, 68, 68, 97, 42, 38, 3, 24, 100, 100],
    [222, 42, 226, 176, 227, 98, 119, 221, 119, 133, 66, 135, 240, 133, 41, 252, 61, 209, 204, 13, 139, 170, 247, 226, 215, 119, 6, 41, 32, 6, 178, 106],
    [4, 9, 16, 103, 186, 202, 190, 11, 67, 78, 231, 244, 48, 159, 112, 242, 147, 4, 153, 250, 13, 137, 159, 145, 46, 58, 204, 251, 141, 43, 82, 219],
    [0, 131, 76, 8, 94, 29, 204, 133, 98, 90, 168, 159, 13, 113, 134, 117, 217, 14, 209, 204, 116, 141, 239, 251, 113, 105, 176, 253, 46, 101, 140, 122],
    [232, 6, 120, 223, 173, 176, 112, 78, 94, 104, 74, 218, 11, 11, 231, 172, 47, 34, 84, 127, 19, 4, 254, 154, 180, 170, 167, 48, 217, 144, 154, 58],
    [75, 100, 43, 206, 60, 145, 171, 170, 137, 226, 137, 170, 65, 187, 204, 138, 128, 136, 177, 34, 159, 165, 175, 11, 122, 95, 28, 90, 118, 197, 136, 202],
    [111, 154, 219, 47, 189, 231, 59, 32, 66, 237, 127, 145, 124, 236, 138, 243, 180, 144, 154, 119, 154, 3, 104, 46, 160, 192, 173, 13, 241, 7, 105, 213],
    [202, 225, 5, 197, 204, 87, 219, 88, 241, 183, 134, 184, 101, 71, 67, 204, 250, 80, 215, 90, 127, 60, 248, 152, 135, 125, 145, 56, 76, 156, 183, 8],
    [144, 76, 248, 96, 236, 79, 150, 87, 201, 93, 200, 101, 166, 87, 119, 186, 134, 119, 123, 246, 134, 116, 140, 233, 122, 226, 80, 221, 69, 218, 94, 149],
    [55, 68, 87, 133, 5, 75, 222, 187, 60, 109, 195, 35, 225, 220, 252, 160, 223, 123, 37, 72, 221, 123, 145, 44, 71, 172, 5, 111, 176, 150, 37, 170],
    [201, 67, 132, 115, 145, 18, 46, 186, 156, 129, 156, 131, 161, 200, 229, 85, 179, 224, 229, 250, 175, 80, 81, 106, 225, 103, 17, 52, 111, 178, 218, 205],
    [238, 172, 28, 211, 117, 83, 191, 134, 45, 190, 171, 174, 52, 199, 94, 125, 135, 203, 198, 236, 104, 71, 192, 219, 236, 137, 59, 76, 248, 92, 250, 91],
    [179, 37, 129, 134, 82, 2, 52, 202, 238, 161, 12, 122, 208, 56, 53, 47, 104, 172, 105, 229, 71, 24, 22, 32, 206, 232, 225, 75, 41, 74, 180, 6],
    [6, 159, 227, 110, 199, 110, 49, 137, 72, 83, 212, 37, 177, 187, 196, 195, 189, 127, 103, 185, 183, 222, 67, 122, 168, 176, 238, 192, 48, 5, 245, 57],
    [188, 195, 30, 98, 161, 141, 24, 190, 76, 246, 82, 9, 10, 64, 77, 155, 142, 155, 226, 42, 254, 235, 45, 75, 78, 226, 226, 82, 213, 64, 147, 111],
    [18, 224, 77, 129, 141, 59, 109, 251, 253, 71, 211, 186, 75, 89, 8, 210, 4, 107, 68, 58, 126, 92, 108, 234, 8, 68, 65, 185, 112, 113, 191, 176],
    [203, 150, 60, 77, 15, 7, 62, 123, 167, 92, 232, 120, 10, 180, 41, 158, 151, 47, 180, 123, 48, 125, 246, 163, 175, 77, 233, 178, 175, 80, 132, 69],
    [13, 80, 180, 250, 156, 162, 176, 222, 76, 178, 89, 5, 82, 119, 40, 133, 132, 171, 52, 32, 78, 139, 203, 134, 91, 4, 57, 14, 251, 83, 95, 241],
    [121, 139, 246, 69, 116, 41, 78, 169, 210, 22, 10, 86, 163, 250, 216, 95, 60, 84, 77, 149, 46, 219, 186, 154, 99, 16, 168, 136, 154, 230, 221, 36],
    [27, 66, 52, 241, 37, 168, 22, 252, 114, 218, 26, 217, 217, 105, 24, 77, 183, 134, 132, 192, 153, 233, 12, 3, 47, 223, 158, 132, 142, 82, 223, 118],
    [59, 109, 76, 24, 23, 102, 102, 140, 51, 58, 196, 75, 42, 213, 236, 84, 97, 187, 162, 219, 133, 154, 148, 104, 188, 128, 93, 78, 151, 241, 145, 14],
    [164, 204, 223, 177, 22, 233, 125, 95, 232, 30, 13, 87, 1, 184, 124, 54, 199, 220, 242, 121, 125, 112, 239, 92, 70, 8, 186, 89, 248, 14, 171, 57],
    [4, 92, 89, 202, 44, 223, 191, 204, 253, 3, 143, 243, 154, 27, 204, 200, 158, 102, 130, 206, 127, 42, 214, 68, 210, 95, 61, 71, 100, 164, 254, 69],
    [228, 135, 138, 5, 26, 91, 162, 69, 106, 142, 190, 201, 196, 84, 229, 189, 203, 16, 164, 69, 17, 215, 151, 47, 43, 38, 241, 227, 34, 181, 169, 84],
    [124, 123, 135, 232, 23, 109, 240, 80, 116, 168, 195, 138, 117, 75, 179, 39, 87, 196, 201, 254, 204, 98, 185, 28, 179, 144, 111, 132, 200, 52, 64, 69],
    [230, 21, 211, 248, 172, 195, 12, 66, 88, 136, 95, 14, 117, 120, 213, 232, 215, 47, 188, 1, 33, 41, 162, 59, 130, 150, 7, 161, 196, 101, 137, 83],
    [30, 186, 53, 17, 199, 144, 155, 172, 178, 77, 97, 68, 229, 249, 236, 252, 165, 214, 208, 146, 10, 110, 38, 128, 244, 235, 239, 6, 217, 169, 202, 207],
    [163, 154, 255, 216, 217, 82, 190, 47, 199, 240, 15, 212, 148, 128, 140, 70, 112, 96, 145, 96, 121, 108, 31, 241, 95, 201, 243, 185, 96, 18, 138, 40],
    [183, 48, 151, 238, 109, 129, 246, 173, 15, 82, 66, 194, 145, 250, 25, 36, 23, 156, 211, 245, 213, 116, 90, 158, 180, 241, 253, 227, 142, 36, 146, 126],
    [132, 84, 4, 48, 37, 208, 111, 33, 50, 248, 79, 118, 181, 211, 239, 60, 152, 221, 128, 2, 57, 190, 48, 193, 171, 77, 154, 244, 223, 149, 64, 230],
    [72, 238, 4, 130, 85, 234, 140, 98, 165, 254, 132, 91, 91, 99, 183, 108, 195, 178, 115, 43, 221, 93, 148, 227, 196, 253, 62, 58, 173, 110, 195, 142],
    [112, 12, 216, 34, 243, 115, 85, 92, 229, 72, 35, 54, 86, 235, 50, 122, 222, 26, 64, 95, 239, 204, 99, 61, 219, 169, 32, 180, 48, 63, 115, 47],
    [168, 1, 135, 186, 168, 171, 173, 224, 94, 119, 81, 51, 22, 213, 114, 191, 216, 31, 162, 176, 141, 124, 121, 113, 144, 198, 86, 225, 4, 50, 201, 124],
    [41, 50, 15, 15, 136, 184, 31, 172, 36, 74, 50, 170, 169, 159, 246, 245, 181, 96, 158, 186, 24, 204, 5, 211, 5, 215, 238, 213, 198, 179, 128, 67],
    [249, 246, 135, 211, 191, 12, 26, 173, 162, 65, 93, 94, 154, 130, 197, 113, 165, 49, 33, 88, 172, 137, 132, 74, 209, 57, 49, 164, 205, 158, 210, 21],
    [40, 181, 199, 200, 60, 225, 129, 107, 27, 134, 49, 222, 212, 155, 69, 148, 39, 163, 175, 11, 189, 235, 171, 91, 136, 1, 138, 113, 112, 228, 20, 159],
    [77, 242, 127, 14, 98, 114, 180, 157, 138, 18, 99, 205, 66, 89, 51, 14, 153, 69, 110, 216, 60, 109, 207, 83, 204, 210, 154, 156, 220, 242, 108, 127],
    [43, 141, 129, 45, 18, 142, 251, 180, 152, 202, 205, 42, 132, 121, 245, 230, 98, 6, 201, 203, 237, 154, 70, 72, 126, 29, 134, 163, 254, 153, 165, 170],
    [211, 88, 196, 127, 190, 31, 156, 212, 147, 4, 167, 39, 48, 204, 42, 247, 198, 148, 192, 128, 209, 2, 155, 235, 191, 227, 198, 40, 35, 28, 184, 197],
    [247, 144, 22, 199, 135, 136, 210, 180, 33, 236, 104, 124, 149, 2, 28, 13, 185, 206, 104, 130, 232, 117, 119, 147, 71, 171, 45, 157, 69, 45, 168, 218],
    [32, 27, 235, 22, 40, 136, 240, 130, 104, 86, 216, 83, 59, 168, 155, 223, 246, 121, 0, 133, 41, 10, 247, 227, 172, 30, 24, 5, 54, 213, 59, 242],
    [64, 124, 244, 138, 131, 107, 118, 226, 160, 137, 66, 9, 206, 178, 47, 101, 23, 172, 206, 253, 122, 153, 143, 132, 193, 136, 213, 136, 27, 143, 127, 203],
    [39, 237, 56, 45, 153, 102, 149, 249, 183, 202, 95, 78, 73, 119, 227, 30, 253, 159, 124, 82, 238, 66, 162, 54, 223, 5, 10, 150, 173, 65, 79, 116],
    [183, 148, 96, 103, 119, 79, 117, 84, 212, 78, 54, 145, 48, 254, 194, 205, 20, 72, 0, 146, 117, 218, 160, 211, 28, 155, 188, 187, 86, 212, 161, 150],
    [22, 158, 134, 220, 136, 200, 70, 229, 12, 218, 15, 87, 182, 79, 75, 117, 137, 128, 119, 243, 246, 193, 90, 26, 189, 157, 184, 222, 121, 195, 211, 236],
    [80, 42, 174, 200, 28, 114, 206, 124, 126, 196, 11, 122, 136, 123, 205, 205, 140, 113, 69, 213, 166, 140, 247, 21, 46, 149, 246, 89, 11, 79, 255, 238],
    [19, 95, 99, 184, 7, 22, 194, 86, 129, 13, 32, 210, 230, 211, 255, 75, 187, 8, 249, 158, 205, 206, 27, 168, 158, 184, 136, 94, 137, 55, 165, 19],
    [9, 204, 255, 83, 244, 172, 118, 86, 159, 25, 5, 26, 81, 88, 146, 124, 96, 10, 60, 88, 25, 18, 185, 48, 135, 63, 99, 229, 206, 76, 12, 224],
    [109, 253, 187, 146, 148, 71, 251, 162, 170, 112, 207, 170, 19, 197, 159, 34, 228, 192, 7, 55, 4, 86, 223, 124, 225, 101, 40, 18, 84, 22, 38, 36],
    [103, 43, 238, 144, 166, 210, 219, 243, 173, 100, 26, 208, 172, 187, 193, 195, 182, 136, 18, 252, 18, 186, 88, 122, 143, 223, 21, 58, 96, 20, 218, 1],
    [74, 128, 8, 181, 212, 144, 163, 4, 70, 27, 203, 81, 107, 8, 44, 226, 63, 181, 5, 88, 232, 101, 90, 206, 218, 98, 154, 184, 168, 47, 198, 142],
    [163, 36, 157, 139, 213, 17, 14, 174, 237, 67, 144, 187, 39, 222, 233, 212, 185, 7, 110, 135, 216, 43, 205, 106, 48, 206, 190, 1, 166, 120, 100, 120],
    [70, 148, 185, 147, 253, 105, 153, 236, 131, 97, 177, 34, 250, 143, 243, 25, 97, 198, 230, 168, 105, 37, 47, 121, 31, 120, 63, 103, 204, 60, 16, 98],
    [71, 94, 10, 25, 14, 45, 19, 239, 40, 196, 66, 166, 63, 205, 162, 63, 26, 166, 204, 46, 128, 52, 25, 200, 80, 238, 92, 20, 210, 122, 20, 52],
    [233, 229, 183, 84, 114, 241, 140, 254, 61, 164, 42, 238, 192, 104, 211, 131, 112, 230, 105, 159, 179, 170, 107, 99, 55, 42, 64, 0, 154, 43, 249, 94],
    [76, 69, 22, 4, 128, 17, 68, 143, 247, 3, 52, 50, 230, 249, 23, 119, 33, 160, 131, 53, 127, 251, 166, 165, 50, 193, 163, 126, 56, 223, 192, 200],
    [192, 220, 174, 230, 230, 181, 109, 112, 103, 70, 49, 35, 251, 104, 70, 157, 0, 136, 56, 47, 235, 172, 128, 26, 190, 192, 3, 238, 74, 161, 93, 12],
    [217, 254, 39, 243, 216, 7, 167, 196, 100, 103, 50, 95, 113, 137, 73, 94, 130, 176, 153, 206, 46, 20, 197, 177, 108, 199, 102, 151, 250, 144, 159, 129],
    [65, 237, 236, 228, 45, 99, 232, 217, 191, 81, 90, 155, 166, 147, 46, 28, 32, 203, 201, 245, 165, 209, 52, 100, 90, 219, 93, 177, 185, 115, 126, 163],
    [187, 3, 129, 193, 62, 8, 23, 32, 19, 85, 231, 215, 0, 183, 98, 63, 14, 152, 82, 135, 173, 215, 135, 18, 161, 20, 7, 201, 247, 84, 239, 200],
    [117, 61, 155, 160, 127, 40, 203, 22, 182, 209, 140, 189, 47, 64, 111, 155, 96, 157, 94, 150, 89, 0, 228, 56, 42, 154, 138, 85, 189, 14, 74, 65],
    [147, 24, 17, 222, 126, 247, 160, 94, 186, 12, 199, 194, 76, 13, 223, 222, 95, 229, 218, 222, 14, 22, 14, 56, 184, 220, 130, 27, 187, 27, 146, 146],
    [228, 154, 232, 205, 185, 157, 58, 87, 155, 221, 115, 105, 15, 88, 104, 207, 137, 47, 59, 181, 111, 18, 110, 186, 106, 136, 136, 139, 31, 35, 42, 252],
    [159, 226, 188, 108, 202, 160, 83, 252, 189, 15, 17, 232, 52, 52, 162, 113, 125, 115, 229, 225, 53, 147, 170, 202, 234, 64, 103, 110, 135, 74, 61, 138],
    [50, 189, 145, 4, 101, 249, 202, 35, 32, 181, 94, 10, 69, 253, 123, 151, 1, 77, 43, 67, 12, 88, 175, 39, 209, 101, 165, 71, 251, 68, 54, 105],
    [77, 160, 234, 167, 231, 135, 92, 84, 79, 70, 36, 240, 237, 239, 225, 167, 13, 92, 212, 214, 85, 237, 229, 142, 207, 114, 56, 100, 135, 211, 38, 168],
    [20, 175, 218, 158, 176, 170, 147, 148, 135, 162, 92, 99, 158, 229, 236, 81, 124, 10, 186, 120, 159, 90, 167, 115, 180, 48, 151, 236, 50, 104, 78, 66],
    [139, 23, 99, 49, 119, 193, 92, 225, 153, 127, 4, 223, 150, 105, 26, 165, 48, 105, 171, 196, 233, 24, 189, 172, 30, 164, 224, 101, 43, 195, 202, 165],
    [105, 77, 36, 198, 130, 131, 185, 154, 213, 238, 92, 234, 163, 93, 157, 228, 221, 85, 69, 221, 122, 56, 95, 75, 24, 250, 133, 178, 220, 109, 226, 186],
    [212, 118, 206, 1, 195, 120, 123, 202, 176, 84, 162, 207, 72, 214, 175, 109, 211, 3, 160, 235, 84, 158, 33, 167, 65, 37, 19, 47, 121, 217, 12, 54],
    [10, 70, 91, 204, 238, 238, 65, 100, 251, 107, 196, 224, 8, 103, 180, 164, 117, 50, 38, 89, 17, 208, 155, 240, 136, 52, 62, 36, 240, 136, 58, 54],
    [118, 2, 245, 88, 143, 145, 181, 12, 96, 227, 103, 130, 21, 212, 184, 98, 198, 65, 27, 242, 232, 218, 63, 57, 2, 7, 126, 152, 85, 6, 176, 235],
    [165, 197, 223, 103, 233, 137, 96, 169, 167, 129, 111, 219, 30, 249, 151, 11, 84, 139, 66, 82, 101, 240, 141, 54, 0, 156, 70, 51, 56, 114, 98, 147],
    [218, 190, 74, 210, 232, 225, 50, 99, 102, 43, 63, 154, 195, 10, 222, 127, 23, 111, 247, 207, 30, 254, 26, 252, 31, 164, 217, 162, 26, 153, 118, 250],
    [53, 98, 145, 84, 31, 117, 211, 72, 223, 38, 200, 116, 216, 212, 253, 154, 236, 129, 80, 81, 60, 118, 140, 148, 175, 52, 160, 111, 208, 52, 2, 85],
    [236, 188, 74, 117, 38, 98, 25, 209, 42, 248, 106, 124, 191, 220, 29, 128, 59, 178, 155, 1, 37, 136, 253, 70, 139, 106, 140, 221, 139, 52, 44, 90],
    [202, 25, 203, 206, 82, 222, 52, 29, 100, 198, 155, 225, 153, 86, 248, 176, 215, 109, 70, 253, 224, 88, 39, 119, 247, 136, 25, 97, 39, 24, 252, 84],
    [82, 57, 81, 1, 241, 94, 200, 116, 30, 79, 9, 99, 151, 18, 64, 129, 231, 221, 137, 159, 51, 204, 169, 71, 65, 185, 116, 32, 211, 206, 67, 146],
    [164, 107, 195, 32, 250, 166, 96, 158, 93, 117, 233, 72, 34, 203, 163, 73, 184, 18, 159, 242, 115, 53, 84, 116, 32, 172, 252, 34, 247, 37, 69, 187],
    [172, 7, 30, 136, 254, 71, 229, 72, 47, 65, 159, 147, 243, 46, 85, 160, 199, 139, 30, 122, 252, 96, 251, 93, 112, 191, 160, 177, 85, 217, 107, 231],
    [232, 11, 239, 215, 249, 36, 191, 89, 139, 135, 60, 55, 147, 165, 86, 47, 160, 190, 176, 192, 5, 51, 120, 221, 155, 164, 180, 139, 129, 169, 158, 213],
    [188, 33, 178, 133, 31, 60, 101, 5, 66, 251, 206, 76, 32, 200, 118, 6, 67, 131, 225, 200, 234, 26, 90, 56, 92, 234, 54, 45, 247, 78, 127, 64],
    [46, 220, 152, 104, 71, 226, 9, 180, 1, 110, 20, 26, 109, 200, 113, 109, 50, 7, 53, 15, 65, 105, 105, 56, 45, 67, 21, 57, 191, 41, 46, 74],
    
    ];

    #[test]
    fn hash_variable_len_bytes() {
		let mut sha256 = Sha256::new();
        for i in 0..HASHES.len() {
            let mut message_bytes = Vec::<u8>::new();
            for _ in 0..=i {
                message_bytes.push(97); // 'a'
            }
            println!("testing msg of len {}", message_bytes.len());
            let hash = sha256.digest(&message_bytes);
            println!("hash: {:?}", hash);
            println!("expected: {:?}", HASHES[i]);
            assert_eq!(hash, HASHES[i], "hashes[{}] with {}x'a'", i, i+1);
        }
    }

    #[test]
    fn hash_variable_len_bytes_shuffled() {
        // deliberately shuffle the test cases to avoid any potential order dependency

        let mut rng = Rng::new(0);

        let limit = 10_000;
        let mut count: usize = 0;
        let mut sha256 = Sha256::new();
        loop {
            let mut message_bytes = Vec::<u8>::new();
            let i = (rng.next() % HASHES.len() as u64) as usize;
            println!("i {}", i);
            for _ in 0..=i {
                message_bytes.push(97); // 'a'
            }
            println!("testing msg of len {}", message_bytes.len());
            let hash = sha256.digest(&message_bytes);
            println!("hash: {:?}", hash);
            println!("expected: {:?}", HASHES[i]);
            assert_eq!(hash, HASHES[i], "hashes[{}] with {}x'a'", i, i+1);

            count += 1;
            if count == limit {
                break;            
            }
        }
        println!("total test cases: {}", count);
    }

}
