//! Throughput benchmarks comparing this workspace's hash crates against the
//! RustCrypto crates, `ring`, and `openssl` (the latter two using hardware crypto
//! where available). Each group sweeps a range of input sizes.
//!
//! Run: `cargo bench -p benchmarks`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use digest::Digest; // shared RustCrypto Digest trait (sha2/sha1/md-5/sha3 all use digest 0.10)

const SIZES: &[usize] = &[16, 64, 1024, 8192, 1_048_576];

fn data_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 31 + 7) as u8).collect()
}

/// Benchmark one of our `new()` + `digest()` hashers.
macro_rules! bench_ours {
    ($group:expr, $size:expr, $data:expr, $name:expr, $ctor:expr) => {
        $group.bench_with_input(BenchmarkId::new($name, $size), $data, |b, d| {
            let mut h = $ctor;
            b.iter(|| h.digest(black_box(d)));
        });
    };
}

/// Benchmark a RustCrypto one-shot `Digest::digest`.
macro_rules! bench_rc {
    ($group:expr, $size:expr, $data:expr, $name:expr, $ty:ty) => {
        $group.bench_with_input(BenchmarkId::new($name, $size), $data, |b, d| {
            b.iter(|| <$ty>::digest(black_box(d)));
        });
    };
}

/// Benchmark a `ring` digest.
macro_rules! bench_ring {
    ($group:expr, $size:expr, $data:expr, $alg:expr) => {
        $group.bench_with_input(BenchmarkId::new("ring", $size), $data, |b, d| {
            b.iter(|| ring::digest::digest($alg, black_box(d)));
        });
    };
}

fn bench_sha256(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha256");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_256::Sha256::new());
        bench_ours!(g, size, &data, "ours_sha_ni", sha_256_ni::Sha256::new());
        bench_rc!(g, size, &data, "rustcrypto", sha2::Sha256);
        bench_ring!(g, size, &data, &ring::digest::SHA256);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| openssl::sha::sha256(black_box(d)));
        });
    }
    g.finish();
}

fn bench_sha224(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha224");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_224::Sha224::new());
        bench_ours!(g, size, &data, "ours_sha_ni", sha_224_ni::Sha224::new());
        bench_rc!(g, size, &data, "rustcrypto", sha2::Sha224);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| openssl::sha::sha224(black_box(d)));
        });
    }
    g.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha512");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_512::Sha512::new());
        bench_rc!(g, size, &data, "rustcrypto", sha2::Sha512);
        bench_ring!(g, size, &data, &ring::digest::SHA512);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| openssl::sha::sha512(black_box(d)));
        });
    }
    g.finish();
}

fn bench_sha384(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha384");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_384::Sha384::new());
        bench_rc!(g, size, &data, "rustcrypto", sha2::Sha384);
        bench_ring!(g, size, &data, &ring::digest::SHA384);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| openssl::sha::sha384(black_box(d)));
        });
    }
    g.finish();
}

fn bench_sha512_256(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha512_256");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_512_256::Sha512_256::new());
        bench_rc!(g, size, &data, "rustcrypto", sha2::Sha512_256);
    }
    g.finish();
}

fn bench_sha512_224(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha512_224");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_512_224::Sha512_224::new());
        bench_rc!(g, size, &data, "rustcrypto", sha2::Sha512_224);
    }
    g.finish();
}

fn bench_sha1(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha1");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_1::Sha1::new());
        bench_ours!(g, size, &data, "ours_sha_ni", sha_1_ni::Sha1::new());
        bench_rc!(g, size, &data, "rustcrypto", sha1::Sha1);
        bench_ring!(g, size, &data, &ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| openssl::sha::sha1(black_box(d)));
        });
    }
    g.finish();
}

fn bench_md5(c: &mut Criterion) {
    let mut g = c.benchmark_group("md5");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", md_5::Md5::new());
        bench_rc!(g, size, &data, "rustcrypto", md5::Md5);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| openssl::hash::hash(openssl::hash::MessageDigest::md5(), black_box(d)).unwrap());
        });
    }
    g.finish();
}

fn bench_sha3_256(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha3_256");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", sha_3::Sha3_256::new());
        bench_rc!(g, size, &data, "rustcrypto", sha3::Sha3_256);
        g.bench_with_input(BenchmarkId::new("openssl", size), &data, |b, d| {
            b.iter(|| {
                openssl::hash::hash(openssl::hash::MessageDigest::sha3_256(), black_box(d)).unwrap()
            });
        });
    }
    g.finish();
}

fn bench_blake3(c: &mut Criterion) {
    let mut g = c.benchmark_group("blake3");
    for &size in SIZES {
        let data = data_of(size);
        g.throughput(Throughput::Bytes(size as u64));
        bench_ours!(g, size, &data, "ours_portable", blake3_portable::Blake3::new());
        bench_ours!(g, size, &data, "ours_simd", blake3_simd::Blake3::new());
        g.bench_with_input(BenchmarkId::new("official_blake3", size), &data, |b, d| {
            b.iter(|| blake3::hash(black_box(d)));
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_sha224,
    bench_sha512,
    bench_sha384,
    bench_sha512_256,
    bench_sha512_224,
    bench_sha1,
    bench_md5,
    bench_sha3_256,
    bench_blake3,
);
criterion_main!(benches);
