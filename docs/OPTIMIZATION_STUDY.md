# Optimisation study: how far can portable code be pushed?

Goal: research the standard software speed-up techniques for these hash algorithms,
implement them as isolated variants, benchmark them, and determine whether a
**substantial performance gain over other libraries** (RustCrypto / ring / OpenSSL)
is attainable.

Method: the convergence harness (interleaved, ratio-based — see
[`BENCHMARKS.md`](BENCHMARKS.md)) on an i7-1185G7, `target-cpu=native`, pinned to one
core. Experimental crates: `sha256_variants`, `sha512_variants`, `sha3_variants`
(all `publish = false`). Every variant is fuzz-tested for correctness against the
reference crate before being benchmarked.

## Techniques researched

| Technique | What it does | Result here |
|-----------|--------------|-------------|
| **Loop unrolling** | amortise loop overhead, expose ILP | **Big win, already in use** — see below |
| **Register renaming** (no-copy rounds) | avoid `h=g; g=f; …` copies by rotating names | **No effect** — LLVM already does this via SSA |
| **K+W pre-combination** | fold `W[i]+K[i]` in the schedule, off the critical path | small win (~5%) |
| **Bounds-check elision** (`get_unchecked`) | drop array bounds checks | small win (~10%) |
| **Full permutation unroll** (Keccak) | constant indices, no modulo / table loads | **regressed** (~-14%) |
| **SHA-NI / SIMD hardware** | dedicated instructions | the ceiling (already used by `*_ni` crates) |

## SHA-256 variant results (speedup vs shipped `sha_256`)

| variant | 1 KiB | 1 MiB | note |
|---------|-------|-------|------|
| A_naive (no manual unroll) | 0.70× | 0.66× | unrolling is worth ~1.5× |
| B_unroll8_rotating (current style) | 1.06× | 1.03× | ≈ shipped |
| C_unroll8_renamed | 1.08× | 1.06× | renaming ≈ no-op |
| D_renamed_kw | 1.10× | 1.08× | +K+W |
| F_renamed_unchecked | 1.14× | 1.13× | +unchecked |
| **G_renamed_kw_unchecked** | **1.18×** | **1.13×** | combined best scalar |
| rustcrypto (SHA-NI) | 6.10× | 6.19× | **hardware ceiling** |

Takeaway: the best portable scalar SHA-256 is ~1.13–1.18× our current crate, but
still **~6× slower than SHA-NI**. No scalar technique closes that gap; dedicated
instructions win. Our `sha_256_ni` already matches RustCrypto's SHA-NI.

## SHA-512 variant results (speedup vs RustCrypto)

| impl | 1 KiB | 1 MiB |
|------|-------|-------|
| current `sha_512` | 0.89× | 0.85× |
| **opt (K+W + unchecked)** | **0.94×** | **0.91×** |
| rustcrypto | 1.00× | 1.00× |
| ring | 1.09× | 1.07× |
| openssl | 1.02× | 1.25× |

Takeaway: the scalar tricks moved us from 0.85× to 0.91× RustCrypto — closer, but
**still behind** all three libraries. They use AVX2-scheduled SHA-512 kernels; pure
scalar cannot match that. Beating them needs an AVX2 message schedule.

## SHA-3 variant results (speedup vs shipped `sha_3`)

| impl | 1 KiB | 1 MiB |
|------|-------|-------|
| current `sha_3` | 1.00× | 1.00× |
| opt (fully-unrolled Keccak) | 0.87× | 0.86× |
| rustcrypto | 0.90× | 0.91× |
| openssl | 1.60× | 1.66× |

Takeaway: our shipped SHA-3 already **beats RustCrypto (~1.11×)**, and the manual
full-unroll **made it slower** — the compact loop form is the scalar sweet spot.
OpenSSL's Keccak is ~1.7× ahead (lane-complementing + tuned scheduling), which a
portable scalar rewrite does not reach.

## Conclusion

**A substantial single-stream speed gain over these libraries is not attainable in
portable Rust.** They are mature and sit at hardware/ISA ceilings:

- **SHA-1 / SHA-256 / SHA-224** — SHA-NI hardware. Our `*_ni` crates already match
  it; scalar code is ~6× behind by definition.
- **SHA-512 family** — AVX2-scheduled kernels. Our best scalar reaches ~0.91× and
  cannot overtake without AVX2.
- **SHA-3** — we already beat RustCrypto; OpenSSL's tuned Keccak stays ~1.7× ahead.
- **MD5** — on par with RustCrypto.
- **BLAKE3** — the official crate's AVX2/AVX-512 multi-chunk `hash_many` is ~8×
  our SSE4.1 single-block kernel on large inputs.

### What is worth keeping

The combined scalar win (**`get_unchecked` + K+W pre-combination**) is a free
~13% (SHA-256) / ~7% (SHA-512) on the portable crates with no API or `no_std`
change. It is a candidate to fold into the shipped portable crates.

### The one genuine path to "substantially beat the libraries"

**Batched multi-lane SIMD.** RustCrypto/ring/OpenSSL expose only single-message
one-shot hashing. For workloads that hash *many independent messages*, an 8-way
AVX2 (or 16-way AVX-512) kernel hashes 8/16 messages in parallel — one per SIMD
lane — at an aggregate throughput that **exceeds even single-stream SHA-NI**,
because SHA-NI can only advance one stream at a time. This is a different API
("hash these N buffers") and a substantial implementation effort (transposed state,
per-lane padding), but it is the honest answer to *how you actually go faster than
these libraries*. It is scoped here as the recommended next project rather than
built, because it changes the public contract.
