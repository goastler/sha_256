//! SIMD-accelerated BLAKE3 (256-bit output) using the SSE4.1 single-block
//! vectorized compression, with runtime CPU detection and a portable fallback.
//!
//! BLAKE3's 16-word compression state is a 4x4 matrix, so each round's four G
//! mixings vectorize into 4-lane `__m128i` operations (the canonical BLAKE3 SSE4.1
//! kernel). This speeds up **every** compression — chunk blocks, parent nodes, and
//! root output — regardless of input size. The tree/chunk machinery is the same as
//! the `blake3_portable` crate, with only the compression function swapped.
//!
//! Scope / honesty: this is the AVX2-era *single-block* SIMD tier. The official
//! `blake3` crate additionally runs 8 chunks in parallel (AVX2 `hash_many`), plus
//! AVX-512 and multithreading, so it remains faster on large inputs. The 8-way
//! multi-chunk path is documented as future work in `docs/ACCELERATION.md`.
//!
//! When SSE4.1 is unavailable this crate delegates to `blake3_portable`.

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// A BLAKE3 hasher that uses the SSE4.1 fast path when available, else the
/// portable fallback.
pub struct Blake3 {
    fallback: blake3_portable::Blake3,
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            fallback: blake3_portable::Blake3::new(),
        }
    }

    /// Computes the 256-bit BLAKE3 digest, using SSE4.1 when available.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 32] {
        #[cfg(target_arch = "x86_64")]
        {
            if fast_path_available() {
                return simd_hash(msg);
            }
        }
        self.fallback.digest(msg)
    }
}

/// Returns true if the SSE4.1 fast path will be used on this CPU.
pub fn fast_path_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("sse4.1")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// SSE4.1 compression kernel (canonical BLAKE3 sse41 sequence).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const fn mm_shuffle(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

#[cfg(target_arch = "x86_64")]
mod sse41 {
    use super::{mm_shuffle, IV};
    use core::arch::x86_64::*;

    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn rot16(x: __m128i) -> __m128i {
        _mm_shuffle_epi8(
            x,
            _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2),
        )
    }
    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn rot12(x: __m128i) -> __m128i {
        _mm_xor_si128(_mm_srli_epi32::<12>(x), _mm_slli_epi32::<20>(x))
    }
    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn rot8(x: __m128i) -> __m128i {
        _mm_shuffle_epi8(
            x,
            _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1),
        )
    }
    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn rot7(x: __m128i) -> __m128i {
        _mm_xor_si128(_mm_srli_epi32::<7>(x), _mm_slli_epi32::<25>(x))
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn shuffle_ps2<const IMM: i32>(a: __m128i, b: __m128i) -> __m128i {
        _mm_castps_si128(_mm_shuffle_ps::<IMM>(_mm_castsi128_ps(a), _mm_castsi128_ps(b)))
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn g1(
        row0: &mut __m128i,
        row1: &mut __m128i,
        row2: &mut __m128i,
        row3: &mut __m128i,
        m: __m128i,
    ) {
        *row0 = _mm_add_epi32(_mm_add_epi32(*row0, m), *row1);
        *row3 = _mm_xor_si128(*row3, *row0);
        *row3 = rot16(*row3);
        *row2 = _mm_add_epi32(*row2, *row3);
        *row1 = _mm_xor_si128(*row1, *row2);
        *row1 = rot12(*row1);
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn g2(
        row0: &mut __m128i,
        row1: &mut __m128i,
        row2: &mut __m128i,
        row3: &mut __m128i,
        m: __m128i,
    ) {
        *row0 = _mm_add_epi32(_mm_add_epi32(*row0, m), *row1);
        *row3 = _mm_xor_si128(*row3, *row0);
        *row3 = rot8(*row3);
        *row2 = _mm_add_epi32(*row2, *row3);
        *row1 = _mm_xor_si128(*row1, *row2);
        *row1 = rot7(*row1);
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn diagonalize(row0: &mut __m128i, row2: &mut __m128i, row3: &mut __m128i) {
        *row0 = _mm_shuffle_epi32::<{ mm_shuffle(2, 1, 0, 3) }>(*row0);
        *row3 = _mm_shuffle_epi32::<{ mm_shuffle(1, 0, 3, 2) }>(*row3);
        *row2 = _mm_shuffle_epi32::<{ mm_shuffle(0, 3, 2, 1) }>(*row2);
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    unsafe fn undiagonalize(row0: &mut __m128i, row2: &mut __m128i, row3: &mut __m128i) {
        *row0 = _mm_shuffle_epi32::<{ mm_shuffle(0, 3, 2, 1) }>(*row0);
        *row3 = _mm_shuffle_epi32::<{ mm_shuffle(1, 0, 3, 2) }>(*row3);
        *row2 = _mm_shuffle_epi32::<{ mm_shuffle(2, 1, 0, 3) }>(*row2);
    }

    /// Single-block BLAKE3 compression. Returns the full 16-word output (matching
    /// the portable `compress`): [r0^r2, r1^r3, r2^cv_lo, r3^cv_hi].
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    pub unsafe fn compress(
        cv: &[u32; 8],
        block_words: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 16] {
        let cv_lo = _mm_loadu_si128(cv.as_ptr() as *const __m128i);
        let cv_hi = _mm_loadu_si128(cv[4..].as_ptr() as *const __m128i);

        let mut row0 = cv_lo;
        let mut row1 = cv_hi;
        let mut row2 = _mm_setr_epi32(IV[0] as i32, IV[1] as i32, IV[2] as i32, IV[3] as i32);
        let mut row3 = _mm_setr_epi32(
            counter as u32 as i32,
            (counter >> 32) as u32 as i32,
            block_len as i32,
            flags as i32,
        );

        let mut m0 = _mm_loadu_si128(block_words.as_ptr() as *const __m128i);
        let mut m1 = _mm_loadu_si128(block_words[4..].as_ptr() as *const __m128i);
        let mut m2 = _mm_loadu_si128(block_words[8..].as_ptr() as *const __m128i);
        let mut m3 = _mm_loadu_si128(block_words[12..].as_ptr() as *const __m128i);

        let mut t0;
        let mut t1;
        let mut t2;
        let mut t3;
        let mut tt;

        // Round 1
        t0 = shuffle_ps2::<{ mm_shuffle(2, 0, 2, 0) }>(m0, m1);
        g1(&mut row0, &mut row1, &mut row2, &mut row3, t0);
        t1 = shuffle_ps2::<{ mm_shuffle(3, 1, 3, 1) }>(m0, m1);
        g2(&mut row0, &mut row1, &mut row2, &mut row3, t1);
        diagonalize(&mut row0, &mut row2, &mut row3);
        t2 = shuffle_ps2::<{ mm_shuffle(2, 0, 2, 0) }>(m2, m3);
        t2 = _mm_shuffle_epi32::<{ mm_shuffle(2, 1, 0, 3) }>(t2);
        g1(&mut row0, &mut row1, &mut row2, &mut row3, t2);
        t3 = shuffle_ps2::<{ mm_shuffle(3, 1, 3, 1) }>(m2, m3);
        t3 = _mm_shuffle_epi32::<{ mm_shuffle(2, 1, 0, 3) }>(t3);
        g2(&mut row0, &mut row1, &mut row2, &mut row3, t3);
        undiagonalize(&mut row0, &mut row2, &mut row3);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Rounds 2-7
        for _ in 0..6 {
            t0 = shuffle_ps2::<{ mm_shuffle(3, 1, 1, 2) }>(m0, m1);
            t0 = _mm_shuffle_epi32::<{ mm_shuffle(0, 3, 2, 1) }>(t0);
            g1(&mut row0, &mut row1, &mut row2, &mut row3, t0);
            t1 = shuffle_ps2::<{ mm_shuffle(3, 3, 2, 2) }>(m2, m3);
            tt = _mm_shuffle_epi32::<{ mm_shuffle(0, 0, 3, 3) }>(m0);
            t1 = _mm_blend_epi16::<0xCC>(tt, t1);
            g2(&mut row0, &mut row1, &mut row2, &mut row3, t1);
            diagonalize(&mut row0, &mut row2, &mut row3);
            t2 = _mm_unpacklo_epi64(m3, m1);
            tt = _mm_blend_epi16::<0xC0>(t2, m2);
            t2 = _mm_shuffle_epi32::<{ mm_shuffle(1, 3, 2, 0) }>(tt);
            g1(&mut row0, &mut row1, &mut row2, &mut row3, t2);
            t3 = _mm_unpackhi_epi32(m1, m3);
            tt = _mm_unpacklo_epi32(m2, t3);
            t3 = _mm_shuffle_epi32::<{ mm_shuffle(0, 1, 3, 2) }>(tt);
            g2(&mut row0, &mut row1, &mut row2, &mut row3, t3);
            undiagonalize(&mut row0, &mut row2, &mut row3);
            m0 = t0;
            m1 = t1;
            m2 = t2;
            m3 = t3;
        }

        let mut out = [0u32; 16];
        _mm_storeu_si128(
            out.as_mut_ptr() as *mut __m128i,
            _mm_xor_si128(row0, row2),
        );
        _mm_storeu_si128(
            out[4..].as_mut_ptr() as *mut __m128i,
            _mm_xor_si128(row1, row3),
        );
        _mm_storeu_si128(
            out[8..].as_mut_ptr() as *mut __m128i,
            _mm_xor_si128(row2, cv_lo),
        );
        _mm_storeu_si128(
            out[12..].as_mut_ptr() as *mut __m128i,
            _mm_xor_si128(row3, cv_hi),
        );
        out
    }
}

/// Safe wrapper over the SSE4.1 compression. Only reached on the guarded fast path
/// (callers ensure SSE4.1 is present before driving the SIMD tree).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn simd_compress(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    unsafe { sse41::compress(cv, block_words, counter, block_len, flags) }
}

// ---------------------------------------------------------------------------
// Tree / chunk machinery (same as blake3_portable, compression swapped).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn first_8_words(out: [u32; 16]) -> [u32; 8] {
    out[0..8].try_into().unwrap()
}

#[cfg(target_arch = "x86_64")]
fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    words
}

#[cfg(target_arch = "x86_64")]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

#[cfg(target_arch = "x86_64")]
impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(simd_compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        let mut output_block_counter = 0u64;
        for out_block in out.chunks_mut(2 * OUT_LEN) {
            let words = simd_compress(
                &self.input_chaining_value,
                &self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, out_word) in words.iter().zip(out_block.chunks_mut(4)) {
                out_word.copy_from_slice(&word.to_le_bytes()[..out_word.len()]);
            }
            output_block_counter += 1;
        }
    }
}

#[cfg(target_arch = "x86_64")]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
}

#[cfg(target_arch = "x86_64")]
impl ChunkState {
    fn new(chunk_counter: u64) -> Self {
        Self {
            chaining_value: IV,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_le_bytes(&self.block);
                self.chaining_value = first_8_words(simd_compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let block_words = words_from_le_bytes(&self.block);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn parent_output(left: [u32; 8], right: [u32; 8]) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_chaining_value: IV,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT,
    }
}

#[cfg(target_arch = "x86_64")]
fn parent_cv(left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
    parent_output(left, right).chaining_value()
}

#[cfg(target_arch = "x86_64")]
fn simd_hash(msg: &[u8]) -> [u8; 32] {
    let mut chunk_state = ChunkState::new(0);
    let mut cv_stack = [[0u32; 8]; 54];
    let mut cv_stack_len = 0usize;

    let mut add_chunk = |cv_stack: &mut [[u32; 8]; 54],
                         cv_stack_len: &mut usize,
                         mut new_cv: [u32; 8],
                         mut total_chunks: u64| {
        while total_chunks & 1 == 0 {
            *cv_stack_len -= 1;
            new_cv = parent_cv(cv_stack[*cv_stack_len], new_cv);
            total_chunks >>= 1;
        }
        cv_stack[*cv_stack_len] = new_cv;
        *cv_stack_len += 1;
    };

    let mut input = msg;
    while !input.is_empty() {
        if chunk_state.len() == CHUNK_LEN {
            let chunk_cv = chunk_state.output().chaining_value();
            let total_chunks = chunk_state.chunk_counter + 1;
            add_chunk(&mut cv_stack, &mut cv_stack_len, chunk_cv, total_chunks);
            chunk_state = ChunkState::new(total_chunks);
        }
        let want = CHUNK_LEN - chunk_state.len();
        let take = want.min(input.len());
        chunk_state.update(&input[..take]);
        input = &input[take..];
    }

    let mut output = chunk_state.output();
    let mut remaining = cv_stack_len;
    while remaining > 0 {
        remaining -= 1;
        output = parent_output(cv_stack[remaining], output.chaining_value());
    }
    let mut out = [0u8; 32];
    output.root_output_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        *blake3::hash(msg).as_bytes()
    }

    #[test]
    fn fuzz_vs_reference() {
        let mut rng = Rng::new(0xdead_beef);
        let mut ours = Blake3::new();
        let mut portable = blake3_portable::Blake3::new();
        for len in 0..=2100usize {
            let mut msg = [0u8; 2100];
            for b in msg.iter_mut().take(len) {
                *b = (rng.next() & 0xff) as u8;
            }
            let msg = &msg[..len];
            let got = ours.digest(msg);
            assert_eq!(got, reference(msg), "vs blake3 mismatch at len {}", len);
            assert_eq!(got, portable.digest(msg), "vs portable mismatch at len {}", len);
        }
        for _ in 0..100 {
            let len = (rng.next() % 65536) as usize;
            let mut msg = [0u8; 65536];
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
            assert!(fast_path_available(), "expected SSE4.1 on this test host");
        }
    }
}
