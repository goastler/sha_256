# Acceleration strategy: portable vs speed tiers

This workspace splits each hash algorithm into a **portable tier** and, where
hardware support exists, a separate **speed tier** crate. This document explains
the split, what hardware each algorithm can use, and what is built today vs left
as future work.

## Two tiers, separate crates

| Tier | Crates | `std`? | CPU instructions | Dispatch |
|------|--------|--------|------------------|----------|
| **Portable** | `sha_256`, `sha_224`, `sha_512`, `sha_384`, `sha_512_256`, `sha_512_224`, `sha_1`, `md_5`, `sha_3`, `blake3_portable` | `no_std`, zero deps | none (pure Rust) | n/a |
| **Speed** | `sha_256_ni`, `sha_224_ni`, `sha_1_ni`, `blake3_simd` | `std` | SHA-NI / SSE4.1 | runtime `is_x86_feature_detected!` + portable fallback |

Why separate crates rather than a feature flag?

- The portable crates stay **`no_std` and dependency-free** — the original
  `sha_256` ethos. They never reference `std` or `core::arch` intrinsics.
- The speed crates are unavoidably **`std`** (runtime CPU detection uses
  `std::is_x86_feature_detected!`) and target-specific. Keeping them separate means
  a `no_std` embedded user depends only on the portable crate and pays nothing for
  the speed machinery, while a server user opts into the accelerated crate.
- Each speed crate exposes the **same API** (`Struct::new().digest(&[u8])`) and
  falls back to its portable sibling on CPUs without the relevant feature, so it is
  a drop-in replacement.

## Hardware support per algorithm

| Algorithm | Mainstream x86 instruction? | Speed crate | Notes |
|-----------|------------------------------|-------------|-------|
| SHA-1 | **SHA-NI** (`sha1rnds4`, `sha1msg1/2`, `sha1nexte`) | `sha_1_ni` | |
| SHA-256 | **SHA-NI** (`sha256rnds2`, `sha256msg1/2`) | `sha_256_ni` | |
| SHA-224 | SHA-NI (same as SHA-256) | `sha_224_ni` | reuses `sha_256_ni`'s compression |
| SHA-384/512 family | none on most CPUs | — | see "future work" |
| MD5 | none | — | no instruction exists; portable only |
| SHA-3 (Keccak) | none on x86 | — | portable only (ARMv8.2 has `EOR3`/`RAX1` etc.) |
| BLAKE3 | SSE2/SSE4.1/AVX2/AVX-512 (general SIMD) | `blake3_simd` | SSE4.1 single-block today |

## What is built today

- **SHA-NI crates** (`sha_1_ni`, `sha_256_ni`, `sha_224_ni`): full hardware
  acceleration using the canonical Gulley/noloader instruction sequences. On a
  SHA-NI capable CPU these run the dedicated SHA round instructions; otherwise they
  call the portable sibling.
- **`blake3_simd`**: the canonical BLAKE3 **SSE4.1 single-block** vectorized
  compression. BLAKE3's 16-word state is a 4×4 matrix, so each round's four G
  mixings become 4-lane `__m128i` operations. This accelerates *every* compression
  (chunk blocks, parent nodes, root) regardless of input size.

## Future work (documented, not yet built)

These are deliberately deferred. They are real opportunities, not oversights:

- **BLAKE3 8-way AVX2 `hash_many`.** The single biggest BLAKE3 win is processing
  **8 independent chunks in parallel** across AVX2 lanes (and 16 across AVX-512),
  transposing the data so each lane advances one chunk through its blocks in
  lockstep. This is what the official `blake3` crate does (plus AVX-512 and
  multithreading). `blake3_simd` currently does only the single-block SSE4.1 kernel,
  so on large multi-chunk inputs the official crate remains faster. Adding an AVX2
  `hash_many` path (with SSE4.1 4-way as the fallback width) is the next step.
- **SHA-512 extension.** Recent Intel CPUs (Arrow Lake and later, via the SHA512
  extension / AVX10) add `sha512*` instructions. A `sha_512_ni` crate could use
  them, with the portable crate as fallback on everything older.
- **ARM acceleration.** ARMv8 has SHA-1/SHA-256 instructions, and ARMv8.2 adds
  SHA-512 and SHA-3 (`EOR3`, `RAX1`, `XAR`, `BCAX`) instructions. Equivalent speed
  crates could target `aarch64` with `std::arch::is_aarch64_feature_detected!`.
- **AVX-512 / multithreading for BLAKE3**, matching the official crate's top tier.

## Honesty about BLAKE3

A pure-Rust, single-threaded BLAKE3 — even with SSE4.1 vectorization — will **not**
beat the official `blake3` crate on large inputs. That crate layers AVX2/AVX-512
multi-chunk kernels (hand-written assembly) and optional multithreading on top. Our
goal here is a correct, `no_std` portable implementation plus an honest SSE4.1 speed
tier; the benchmark reports the real gap.
