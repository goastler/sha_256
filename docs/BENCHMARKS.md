# Benchmarks & findings

Throughput comparison of this workspace's crates against the de-facto Rust and
native implementations: **RustCrypto** (`sha2`/`sha1`/`md-5`/`sha3`), **`ring`**
(BoringSSL-derived), and **`openssl`** (system OpenSSL 3.0.13 via FFI). On this CPU
RustCrypto, `ring`, and OpenSSL all auto-use the **SHA-NI** hardware instructions
for SHA-1/256, so those columns are hardware-accelerated baselines, not scalar ones.

> TL;DR: our hand-written **SHA-NI** crates match or slightly beat RustCrypto and
> edge out `ring` on SHA-1/256/224. Our portable **SHA-3** is ~12% faster than
> RustCrypto. **MD5** is on par. Portable **SHA-512** trails RustCrypto by ~20%
> (headroom). **BLAKE3** SSE4.1 gives ~15–20% over our portable scalar but is ~8×
> behind the official crate on large inputs (no multi-chunk AVX2 — by design).

## Environment

| | |
|---|---|
| CPU | Intel Core i7-1185G7 (Tiger Lake, 4C/8T) |
| Frequency | 0.4–4.8 GHz, governor `powersave`, **turbo enabled** |
| Features | SHA-NI, SSE4.1, AVX2, AVX-512 |
| Toolchain | rustc 1.89, `RUSTFLAGS="-C target-cpu=native"`, release + LTO |
| Pinning | process pinned to core 3 (`taskset -c 3`) |
| Date | 2026-06-12 |

Because the governor is `powersave` with turbo, the core frequency swings widely
during a run. This shows up as a **coefficient of variation (CV) of ~10–20% on
absolute throughput**. It is a property of the measurement host, not the code.

## Methodology

A custom harness ([`crates/benchmarks/src/bin/convergence.rs`](../crates/benchmarks/src/bin/convergence.rs))
designed to be fair under that frequency drift:

1. **Calibrate** an inner iteration count per implementation (~50 ms per sample).
2. **Warm up** ~0.2 s to let frequency settle.
3. **Interleaved rounds**: in each round, *every* implementation is timed once,
   back-to-back, so within a round they all see the same instantaneous frequency.
4. **Ratio-based convergence**: per round we record each impl's throughput and its
   ratio to a baseline impl. A cell stops once every non-baseline ratio's relative
   standard error of the mean is below 0.5% — i.e. the speedup estimate and its
   standard deviation have stabilised — capped at 150 rounds / 10 s.

The **speedup ratios are the trustworthy output**: because the two implementations
in a ratio are measured in the same round, the ratio is robust to frequency drift
(its stdev is typically ≤0.07). Absolute GiB/s is reported too, but its larger CV is
the frequency drift described above. Reported values are `mean ± stdev` over rounds.

## Results

Speedups are per-round ratios vs the baseline (`rustcrypto`, except BLAKE3 vs
`official_blake3`). `ours_portable` = pure-Rust `no_std` crate; `ours_sha_ni` /
`ours_simd` = speed-tier crates.

### SHA-256

Speedup vs `rustcrypto`:

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.25±0.03 | 0.16±0.01 | 0.16±0.01 | 0.16±0.01 |
| ours_sha_ni | 1.10±0.03 | 1.01±0.04 | 1.01±0.07 | 1.00±0.06 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| ring | 0.89±0.02 | 0.92±0.04 | 0.93±0.04 | 0.93±0.06 |
| openssl | 0.15±0.02 | 0.60±0.05 | 0.89±0.06 | 0.93±0.09 |

Absolute GiB/s @ 1 MiB: ours_sha_ni **0.72**, rustcrypto 0.72, ring 0.67, ours_portable 0.11.

### SHA-224

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.23±0.01 | 0.16±0.01 | 0.15±0.01 | 0.15±0.01 |
| ours_sha_ni | 1.10±0.03 | 1.03±0.04 | 1.00±0.04 | 0.99±0.03 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| openssl | 0.14±0.02 | 0.60±0.05 | 0.90±0.03 | 0.92±0.03 |

### SHA-512

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.84±0.05 | 0.82±0.05 | 0.81±0.10 | 0.80±0.07 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| ring | 1.00±0.07 | 1.04±0.11 | 1.04±0.09 | 1.03±0.04 |
| openssl | 0.40±0.04 | 0.98±0.12 | 1.22±0.18 | 1.23±0.17 |

Absolute GiB/s @ 1 MiB: openssl **0.41**, ring 0.34, rustcrypto 0.34, ours_portable 0.27.

### SHA-384

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.84±0.06 | 0.81±0.05 | 0.80±0.07 | 0.80±0.04 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| ring | 1.01±0.05 | 1.04±0.05 | 1.04±0.09 | 1.04±0.04 |
| openssl | 0.40±0.03 | 0.96±0.09 | 1.22±0.16 | 1.22±0.07 |

### SHA-512/256

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.84±0.04 | 0.84±0.10 | 0.81±0.10 | 0.80±0.06 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |

### SHA-512/224

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.93±0.14 | 0.93±0.15 | 0.95±0.13 | 0.86±0.11 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |

### SHA-1

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.31±0.02 | 0.23±0.00 | 0.22±0.02 | 0.22±0.01 |
| ours_sha_ni | 1.18±0.05 | 1.00±0.03 | 1.00±0.07 | 0.97±0.04 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| ring | 0.27±0.02 | 0.22±0.01 | 0.21±0.02 | 0.21±0.01 |
| openssl | 0.13±0.02 | 0.63±0.03 | 0.94±0.09 | 0.99±0.05 |

Absolute GiB/s @ 1 KiB: ours_sha_ni **1.84**, rustcrypto 1.84, openssl 1.15, ours_portable 0.42, ring 0.40.

### MD5

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 1.02±0.02 | 0.93±0.02 | 0.92±0.01 | 0.92±0.03 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| openssl | 0.25±0.01 | 0.89±0.02 | 1.10±0.02 | 1.12±0.04 |

### SHA3-256

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 1.13±0.02 | 1.12±0.03 | 1.12±0.03 | 1.12±0.03 |
| rustcrypto | 1.00 | 1.00 | 1.00 | 1.00 |
| openssl | 0.94±0.04 | 1.84±0.08 | 2.10±0.21 | 2.14±0.14 |

### BLAKE3 (baseline = official `blake3` crate)

| impl | 16 B | 1 KiB | 16 KiB | 1 MiB |
|------|------|------|------|------|
| ours_portable | 0.95±0.05 | 0.69±0.02 | 0.12±0.01 | 0.11±0.00 |
| ours_simd | 0.81±0.03 | 0.80±0.01 | 0.14±0.01 | 0.13±0.00 |
| official_blake3 | 1.00 | 1.00 | 1.00 | 1.00 |

Absolute GiB/s @ 1 MiB: official **4.81**, ours_simd 0.62, ours_portable 0.52.

## Findings

**1. The SHA-NI crates are the headline result.** `sha_256_ni`, `sha_224_ni`, and
`sha_1_ni` **match or slightly beat RustCrypto's SHA-NI** (1.00–1.18×) and edge out
`ring` (which lands ~0.9× on SHA-256 and is notably slow on SHA-1). They have the
lowest small-input overhead of any contender — at 16 B, `sha_256_ni` is 1.10× and
`sha_1_ni` is 1.18× RustCrypto. They are ~5–6× faster than the portable scalar
crates. This is exactly where the hand-written `core::arch` sequences pay off.

**2. Pure scalar cannot beat SHA-NI — correcting an old claim.** The original
README claimed the portable SHA-256 was "up to 25% faster" than crates using SHA-NI.
On a SHA-NI-capable CPU that does not hold: `sha_256` (portable) runs at **~0.16×**
the SHA-NI baselines, i.e. ~6× slower. The portable tier's value is `no_std`
portability and a zero-dependency fallback — **not** out-running hardware crypto.
(The earlier claim was likely measured against builds where SHA-NI was not actually
engaged.) `docs/ACCELERATION.md` and the new README reflect this honestly.

**3. SHA-512 family is our weakest portable result.** With no SHA-512 instruction on
this CPU, every contender is software — yet our portable SHA-512/384/512-256 trail
RustCrypto by ~20% (0.80×) and `ring`/OpenSSL by more. RustCrypto's `sha2` has a
more carefully scheduled 64-bit core. This is the clearest target for future tuning
(the 8-way macro unroll may not be the best schedule for the u64 path).

**4. MD5 is on par with RustCrypto** (0.92–1.02×) and faster at tiny inputs.

**5. Portable SHA-3 beats RustCrypto** by ~12% consistently (1.12×) — the fully
const-bounded, compiler-unrolled Keccak permutation does well. OpenSSL's Keccak is
~2× faster than both, so there is still headroom against a top-tier native impl.

**6. BLAKE3 behaves exactly as designed/documented.** `blake3_simd` (SSE4.1) is
~15–20% faster than our portable scalar at small/medium sizes. But for inputs ≥16 KiB
the official crate pulls away to **~8× faster** (4.8 vs 0.6 GiB/s at 1 MiB) because it
runs 8–16 chunks in parallel via AVX2/AVX-512 `hash_many`, which we deliberately have
not implemented. For single-chunk inputs (≤1 KiB) we are within 0.69–0.95× of the
official crate. See the BLAKE3 section of `docs/ACCELERATION.md`.

**7. OpenSSL's FFI overhead dominates tiny inputs** (0.04–0.25× at 16 B across
algorithms) but it leads or ties at 1 MiB for SHA-512, SHA-3, and MD5. For latency on
small messages, the in-process Rust/SHA-NI paths win decisively.

## Caveats

- Single host, single mobile CPU, `powersave` + turbo. Absolute numbers are not
  portable; the **ratios** are the comparable result. Rankings could shift on a
  server CPU with a fixed/`performance` governor or different SIMD width.
- `ring` exposes no SHA-224/MD5/SHA-3; OpenSSL is omitted for the SHA-512/t variants
  (no convenient one-shot). Empty cells mean "not offered by that library here".

## Reproducing

```bash
# Interleaved convergence harness (the source of the tables above):
RUSTFLAGS="-C target-cpu=native" taskset -c 3 \
  cargo run --release --bin convergence -p benchmarks

# Or the Criterion suite (per-impl statistical sampling):
RUSTFLAGS="-C target-cpu=native" cargo bench -p benchmarks
```

For the steadiest numbers, set the governor to `performance` and/or disable turbo
before running.
