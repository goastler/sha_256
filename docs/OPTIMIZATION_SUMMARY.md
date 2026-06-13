# Optimisation research — summary & conclusion

Outcome of the loop "research and produce optimisations until a substantial
performance gain over other libs/impls". Three iterations, all measured with the
interleaved convergence harness on an i7-1185G7 (`target-cpu=native`, pinned core).
Full tables: [`OPTIMIZATION_STUDY.md`](OPTIMIZATION_STUDY.md). Benchmark method:
[`BENCHMARKS.md`](BENCHMARKS.md).

## What the research found

### Techniques that work (worth folding into the shipped crates)
- **Loop unrolling** — ~1.5× (our 8-way is already near-optimal; the un-unrolled
  `naive` variant is 0.67×).
- **`get_unchecked` + K+W pre-combination** — a free **~13% on SHA-256, ~7% on
  SHA-512**, with no API or `no_std` change.

### Techniques that don't (useful negative results)
- **Register renaming** (avoiding the `h=g; g=f; …` copies) — **no effect**. LLVM
  already removes the copies via SSA, so our "copying" code never paid for them.
- **Fully unrolling Keccak** — **regressed ~14%**. The compact loop form is the
  scalar sweet spot; manual unroll just added register pressure and worse codegen.

## The ceiling — why beating the libraries single-stream is unreachable

The comparison libraries are mature and sit at hardware/ISA ceilings:

| Algorithm | Their ceiling | Where we land |
|-----------|---------------|---------------|
| SHA-1 / SHA-256 / SHA-224 | SHA-NI hardware instructions | `*_ni` crates **match** it; scalar is ~6× behind by physics |
| SHA-512 family | AVX2-scheduled kernels | best scalar **0.91×** RustCrypto — can't overtake without AVX2 |
| SHA-3 (Keccak) | OpenSSL tuned asm | we **beat RustCrypto ~1.11×**; OpenSSL stays ~1.7× ahead |
| MD5 | — | on par with RustCrypto |
| BLAKE3 | AVX2/AVX-512 multi-chunk `hash_many` | official ~8× our SSE4.1 single-block on large inputs |

**Conclusion: a substantial single-stream speed gain over RustCrypto / ring /
OpenSSL is not attainable in portable Rust.** We already match the SHA-NI ceiling
(via the `*_ni` crates), beat RustCrypto on SHA-3, and come within ~10% on SHA-512.

## Measured variant results (condensed)

SHA-256 (speedup vs shipped `sha_256`): combined-best scalar
`G_renamed_kw_unchecked` = **1.13–1.18×**; SHA-NI baseline = **6.2×** (the ceiling).

SHA-512 (speedup vs RustCrypto): `current` 0.85× → `opt (K+W + unchecked)` **0.91×**;
ring 1.07×, OpenSSL 1.25×.

SHA-3 (speedup vs shipped `sha_3`): `opt (full unroll)` **0.86×** (regression);
RustCrypto 0.91× (i.e. we beat it ~1.11×); OpenSSL ~1.66×.

## The one genuine path to substantially beat them

**Batched multi-lane SIMD.** Every comparison library hashes only *one* message at a
time. An **8-way AVX2** (or 16-way AVX-512) kernel hashes 8/16 independent messages
in parallel — one per SIMD lane — at aggregate throughput that **exceeds even
single-stream SHA-NI**, because SHA-NI advances only one stream at once. This is the
honest "how you actually go faster than these libraries", but it is:
- a **different API** (`hash(&[&[u8]]) -> Vec<[u8; N]>` / fixed-N batch), and
- a **large implementation** (transposed state across lanes, per-lane padding),
  comparable in effort to a BLAKE3 `hash_many`.

It is scoped here as the recommended next project rather than built, because it
changes the public contract — a decision for the maintainer.

## Recommendation

1. Fold the proven scalar win (`get_unchecked` + K+W) into the portable crates for a
   free ~7–13%.
2. If a *substantial* gain over the libraries is required, implement the batched
   multi-lane AVX2 kernel (new batch API) and benchmark it against running SHA-NI N
   times. Otherwise the single-stream optimisation work is complete: we match or beat
   the libraries everywhere a portable/`_ni` implementation can.
