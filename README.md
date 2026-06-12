# Hashes

A Cargo workspace of fast, hand-optimized hashing algorithms in Rust, grown from
the original `sha_256` crate. Every algorithm reuses the same performance recipe:
`no_std`, stack-only fixed arrays (no heap), partially-unrolled message-schedule and
compression loops, scratch-array reuse across calls, and direct big/little-endian
byte conversions with no intermediate buffers.

## Crates

### Portable tier — `no_std`, zero runtime dependencies

| Crate | Algorithm | Output |
|-------|-----------|--------|
| [`sha_256`](crates/sha_256) | SHA-256 | 32 bytes |
| [`sha_224`](crates/sha_224) | SHA-224 | 28 bytes |
| [`sha_512`](crates/sha_512) | SHA-512 | 64 bytes |
| [`sha_384`](crates/sha_384) | SHA-384 | 48 bytes |
| [`sha_512_256`](crates/sha_512_256) | SHA-512/256 | 32 bytes |
| [`sha_512_224`](crates/sha_512_224) | SHA-512/224 | 28 bytes |
| [`sha_1`](crates/sha_1) | SHA-1 *(legacy/broken)* | 20 bytes |
| [`md_5`](crates/md_5) | MD5 *(legacy/broken)* | 16 bytes |
| [`sha_3`](crates/sha_3) | SHA3-224/256/384/512 | 28/32/48/64 bytes |
| [`blake3_portable`](crates/blake3) | BLAKE3 | 32 bytes |

### Speed tier — `std`, runtime CPU detection + portable fallback

| Crate | Acceleration |
|-------|--------------|
| [`sha_256_ni`](crates/sha_256_ni) | Intel SHA-NI |
| [`sha_224_ni`](crates/sha_224_ni) | Intel SHA-NI |
| [`sha_1_ni`](crates/sha_1_ni) | Intel SHA-NI |
| [`blake3_simd`](crates/blake3_simd) | SSE4.1 vectorized compression |

See [`docs/ACCELERATION.md`](docs/ACCELERATION.md) for the portable-vs-speed strategy,
the hardware-support matrix, and documented future work (BLAKE3 AVX2 `hash_many`,
SHA-512 extension, ARM acceleration).

## Usage

Every crate exposes the same "bytes in, bytes out" API:

```rust
use sha_512::Sha512;

let mut hasher = Sha512::new();
let digest: [u8; 64] = hasher.digest(b"hello");
```

SHA-3 exposes one type per output size; speed crates are drop-in replacements:

```rust
let mut h = sha_3::Sha3_256::new();
let digest: [u8; 32] = h.digest(b"hello");

// Uses SHA-NI when the CPU supports it, else falls back to the portable crate.
let mut h = sha_256_ni::Sha256::new();
let digest: [u8; 32] = h.digest(b"hello");
```

See the [example project](example/) for converting strings/hex to and from bytes.

## Correctness

Each crate is fuzz-tested against the corresponding established crate
(`sha2` / `sha1` / `md-5` / `sha3` / `blake3`) over every input length across the
padding boundaries plus random multi-block inputs, alongside canonical known-answer
vectors. Speed crates additionally cross-check against their portable sibling.

```bash
cargo test --workspace --lib
```

## Benchmarks

The [`benchmarks`](crates/benchmarks) crate (Criterion) compares every crate against
RustCrypto, [`ring`](https://crates.io/crates/ring), and `openssl` (the latter two
using hardware crypto where available), sweeping input sizes from 16 B to 1 MiB.

```bash
cargo bench -p benchmarks
```

There is also a custom **convergence harness** that interleaves all contenders per
round and averages over repeated runs until the speedup estimates (mean ± stdev)
stabilise — fairer than one-at-a-time timing on a CPU whose frequency drifts:

```bash
RUSTFLAGS="-C target-cpu=native" taskset -c 3 \
  cargo run --release --bin convergence -p benchmarks
```

Requires a system OpenSSL for the `openssl` baseline.

**Measured results and analysis: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).**
Headlines on an i7-1185G7: the SHA-NI crates match/beat RustCrypto and `ring` on
SHA-1/256/224; portable SHA-3 is ~12% faster than RustCrypto; MD5 is on par;
portable SHA-512 trails RustCrypto by ~20%; and BLAKE3 SSE4.1 beats our scalar but
is ~8× behind the official crate's multi-chunk AVX2 on large inputs (by design).

## License

Apache-2.0.
