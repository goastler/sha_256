# Multi-algorithm hashing workspace — design

Date: 2026-06-12
Branch: `multi-hash-workspace`

## Goal

Convert the single-crate `sha_256` repo into a Cargo workspace and add a family of
hashing algorithms that reuse the existing SHA-256 performance techniques. Add a
benchmark harness comparing our crates against established libraries and CPU-instruction
implementations. **Benchmarks are built but not run until the user grants permission.**

## Existing optimization techniques (to carry over)

From `src/lib.rs` (SHA-256):
- `#![no_std]`, zero runtime dependencies, stack-only fixed arrays (no heap).
- 8-way **partially unrolled** message-schedule and compression loops.
- Scratch `w` array reused across `digest` calls (struct fields, not locals).
- Direct `from_be_bytes` / `to_be_bytes` — no intermediate byte buffers.
- No SIMD, no asm in the portable tier.

## Crate inventory (15 crates + example)

### Portable tier — `no_std`, zero runtime deps, 8-way unrolled

| Crate | Core | Block | Word | Rounds | Endian | Output |
|-------|------|-------|------|--------|--------|--------|
| `sha_256` (relocated, unchanged) | SHA-256 | 64 B | u32 | 64 | BE | 32 |
| `sha_224` | SHA-256 core | 64 B | u32 | 64 | BE | 28 |
| `sha_512` | SHA-512 | 128 B | u64 | 80 | BE | 64 |
| `sha_384` | SHA-512 core | 128 B | u64 | 80 | BE | 48 |
| `sha_512_256` | SHA-512 core | 128 B | u64 | 80 | BE | 32 |
| `sha_512_224` | SHA-512 core | 128 B | u64 | 80 | BE | 28 |
| `sha_1` | SHA-1 | 64 B | u32 | 80 | BE | 20 |
| `md_5` | MD5 | 64 B | u32 | 64 | **LE** | 16 |
| `sha_3` | Keccak-f[1600] | sponge | u64 | 24 | LE | 28/32/48/64 |
| `blake3` | BLAKE3 | 64 B | u32 | 7 | LE | 32 |

`sha_3` exposes `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512` (one algorithm,
output length is a parameter — duplicating the Keccak permutation across four
crates would be wasteful). SHAKE (XOF) is out of scope.

### Speed tier — separate crates, `std`, `core::arch` intrinsics, runtime dispatch + portable fallback

| Crate | Mechanism | Falls back to |
|-------|-----------|---------------|
| `sha_256_ni` | SHA-NI | portable SHA-256 |
| `sha_224_ni` | SHA-NI (shares sha_256_ni compression) | portable SHA-224 |
| `sha_1_ni` | SHA-NI | portable SHA-1 |
| `blake3_simd` | AVX2 (8-way) + SSE4.1 (4-way) | portable BLAKE3 |

Speed crates use `is_x86_feature_detected!` at runtime (hence `std`) and dispatch
to the fast path, falling back to a bundled portable path on unsupported CPUs.

Why only these four: SHA-NI hardware exists for SHA-1/256/224; BLAKE3 has a
well-defined SIMD design. MD5, SHA-3, and the SHA-512 family have no mainstream
x86 instruction, so a speed crate would just duplicate the portable one — they are
documented as future work (SHA-512 ext, ARM SHA3/SHA2 extensions) in
`docs/ACCELERATION.md`.

### Non-published

- `benchmarks` (`publish = false`).

## Layout

```
Cargo.toml                  # virtual workspace (members + shared release profile)
docs/ACCELERATION.md        # portable-vs-speed strategy, HW matrix, future roadmap
docs/superpowers/specs/     # this design doc
crates/
  sha_256/ sha_224/ sha_512/ sha_384/ sha_512_256/ sha_512_224/
  sha_1/ md_5/ sha_3/ blake3/                       # portable tier
  sha_256_ni/ sha_224_ni/ sha_1_ni/ blake3_simd/    # speed tier
  benchmarks/
example/                    # path dep updated, joins workspace
```

## API (uniform, unchanged from current crate)

Every crate, both tiers, exposes:

```rust
let mut h = Sha512::new();
let digest: [u8; 64] = h.digest(msg_bytes); // bytes in, bytes out
```

`sha_3` types follow the same shape (`Sha3_256::new().digest(..)`).

## Design notes / pitfalls

- **MD5 is the only little-endian algorithm**: word loading and the length field
  are little-endian, unlike every SHA variant. Its padding skeleton must not copy
  SHA's big-endian assumptions.
- **SHA-512 length field is 128-bit** (vs 64-bit for SHA-256/SHA-1), block is 128 B.
- **Core duplication is deliberate**: each crate is self-contained so it can be
  published independently with zero deps (matching how `sha_256` stands alone).
  SHA-224 copies the SHA-256 core (different IV + truncation) rather than sharing it.
- **BLAKE3 honesty**: even with AVX2 intrinsics, a single-threaded crate will not
  fully match the official `blake3` crate (AVX-512 + asm + multithreading).
  Realistic target: correct + `no_std` portable tier; approach the AVX2
  single-threaded tier in `blake3_simd`. The benchmark reports the honest gap.

## Testing (per crate)

- Each portable crate: `fuzz_vs_reference` test hashing thousands of random-length
  inputs (reuse the xorshift `Rng`) asserting equality against the matching
  RustCrypto crate (`sha2` / `sha1` / `md-5` / `sha3` / `blake3`) as a dev-dependency,
  plus canonical vectors (empty, `"abc"`, a multi-block input).
- Each speed crate: fuzz vs **both** its portable sibling and the reference; assert
  the fast path actually engaged on a capable CPU.

## Benchmarks (`crates/benchmarks`, built now, run later)

Criterion groups per algorithm, sweeping input sizes (16 B, 64 B, 1 KiB, 8 KiB, 1 MiB).
Each group pits our portable + speed crates against baselines where supported:

| Baseline | Covers |
|----------|--------|
| RustCrypto (`sha2`, `sha1`, `md-5`, `sha3`, `blake3`) | all |
| `ring` | SHA-1, SHA-256, SHA-384, SHA-512 |
| `openssl` | MD5, SHA-1, SHA-256/384/512, SHA-3 |

`ring`/`openssl` are `std` + need a system OpenSSL lib — fine since `benchmarks`
is `publish = false`. Prerequisite documented.

## Implementation phases

- **P1** Workspace skeleton + relocate `sha_256`
- **P2** SHA-512 core + 512-family + SHA-224
- **P3** SHA-1 + MD5
- **P4** SHA-3
- **P5** portable BLAKE3
- **P6** SHA-NI speed crates
- **P7** BLAKE3 SIMD
- **P8** benchmark harness + `ACCELERATION.md` + push branch to origin

## Git

Branch `multi-hash-workspace` off `main`; commit per phase; push to `origin` when done.
