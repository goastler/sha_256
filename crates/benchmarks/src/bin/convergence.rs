//! Multi-run convergence benchmark harness (interleaved, ratio-based).
//!
//! Naively measuring each implementation to convergence one-at-a-time is unfair on
//! a thermally-constrained CPU: contenders end up measured at different frequency
//! states, so absolute throughput drifts and comparisons are biased. Instead, for
//! each (algorithm, input size) cell this harness:
//!
//!   1. calibrates an inner iteration count per implementation (~50 ms/sample),
//!   2. warms up, then
//!   3. repeats *rounds*; in each round every implementation is timed once,
//!      back-to-back, so they share the same instantaneous frequency/thermal state.
//!      Per round it records each impl's throughput and its ratio to a baseline impl.
//!
//! Convergence is judged on the per-round **ratios** (drift-robust): a cell stops
//! once every non-baseline ratio's relative standard error of the mean is below a
//! tolerance — i.e. the speedup estimates (and their stdev) have stabilised —
//! subject to min/max round counts and a wall-clock cap.
//!
//! Output: per group, a speedup table (mean ± stdev of the ratio) and an absolute
//! GiB/s table (mean, with coefficient of variation — which reflects CPU-frequency
//! drift over the session and is expected to be larger than the ratio's).
//!
//! Run pinned to a core for stability, e.g.:
//!   taskset -c 3 cargo run --release --bin convergence -p benchmarks

use digest::Digest;
use std::hint::black_box;
use std::time::Instant;

const SIZES: &[usize] = &[16, 1024, 16384, 1_048_576];

const TARGET_RUN_SECS: f64 = 0.05;
const WARMUP_SECS: f64 = 0.20;
const MIN_ROUNDS: usize = 15;
const MAX_ROUNDS: usize = 150;
const REL_SEM_TOL: f64 = 0.005; // stop when every ratio's SEM/mean < 0.5%
const MAX_CELL_SECS: f64 = 10.0;

const GIB: f64 = (1u64 << 30) as f64;

type Hasher = Box<dyn FnMut(&[u8])>;

fn data_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 31 + 7) as u8).collect()
}

fn mean_stdev(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = if xs.len() > 1 {
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    (mean, var.sqrt())
}

fn calibrate(f: &mut Hasher, data: &[u8]) -> usize {
    let mut inner = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..inner {
            f(data);
        }
        let el = t.elapsed().as_secs_f64();
        if el >= TARGET_RUN_SECS || inner >= 1 << 30 {
            break;
        }
        if el < 1e-7 {
            inner = inner.saturating_mul(8).max(8);
        } else {
            let scale = (TARGET_RUN_SECS / el * 1.2).clamp(2.0, 16.0);
            inner = ((inner as f64) * scale) as usize;
        }
        inner = inner.max(1);
    }
    inner
}

fn time_once(f: &mut Hasher, data: &[u8], inner: usize) -> f64 {
    let t = Instant::now();
    for _ in 0..inner {
        f(data);
    }
    let el = t.elapsed().as_secs_f64();
    inner as f64 * data.len() as f64 / el
}

struct Cell {
    abs_mean: f64, // bytes/sec
    abs_cv: f64,   // stdev/mean
    ratio_mean: f64,
    ratio_stdev: f64,
    rounds: usize,
}

fn run_group(out: &mut String, name: &str, baseline: &str, mut contenders: Vec<(&str, Hasher)>) {
    // Optional group filter: BENCH_FILTER=substring runs only matching groups.
    if let Ok(f) = std::env::var("BENCH_FILTER") {
        if !f.is_empty() && !name.contains(f.as_str()) {
            return;
        }
    }
    eprintln!("== {} ==", name);
    let n = contenders.len();
    let base_idx = contenders
        .iter()
        .position(|(c, _)| *c == baseline)
        .unwrap_or(0);

    // results[contender][size]
    let mut results: Vec<Vec<Cell>> = (0..n).map(|_| Vec::new()).collect();

    for &size in SIZES {
        let data = data_of(size);

        // Calibrate + warm up each contender.
        let mut inner = vec![1usize; n];
        for i in 0..n {
            inner[i] = calibrate(&mut contenders[i].1, &data);
            let wt = Instant::now();
            while wt.elapsed().as_secs_f64() < WARMUP_SECS {
                for _ in 0..inner[i] {
                    (contenders[i].1)(&data);
                }
            }
        }

        let mut abs: Vec<Vec<f64>> = (0..n).map(|_| Vec::new()).collect();
        let mut ratio: Vec<Vec<f64>> = (0..n).map(|_| Vec::new()).collect();
        let cell_start = Instant::now();

        loop {
            // One interleaved round: time every contender back-to-back.
            let mut this = vec![0.0f64; n];
            for i in 0..n {
                this[i] = time_once(&mut contenders[i].1, &data, inner[i]);
            }
            let base = this[base_idx];
            for i in 0..n {
                abs[i].push(this[i]);
                ratio[i].push(this[i] / base);
            }

            let rounds = abs[0].len();
            if rounds >= MIN_ROUNDS {
                let mut converged = true;
                for i in 0..n {
                    if i == base_idx {
                        continue;
                    }
                    let (m, sd) = mean_stdev(&ratio[i]);
                    let sem = sd / (rounds as f64).sqrt();
                    if m <= 0.0 || sem / m >= REL_SEM_TOL {
                        converged = false;
                        break;
                    }
                }
                if converged {
                    break;
                }
            }
            if rounds >= MAX_ROUNDS || cell_start.elapsed().as_secs_f64() > MAX_CELL_SECS {
                break;
            }
        }

        for i in 0..n {
            let (am, asd) = mean_stdev(&abs[i]);
            let (rm, rsd) = mean_stdev(&ratio[i]);
            results[i].push(Cell {
                abs_mean: am,
                abs_cv: if am > 0.0 { asd / am } else { 0.0 },
                ratio_mean: rm,
                ratio_stdev: rsd,
                rounds: abs[i].len(),
            });
            eprintln!(
                "  {:>16} {:>8}B  {:7.3} GiB/s  CV {:4.1}%  {:.2}x  ({} rounds)",
                contenders[i].0,
                size,
                results[i].last().unwrap().abs_mean / GIB,
                100.0 * results[i].last().unwrap().abs_cv,
                rm,
                results[i].last().unwrap().rounds,
            );
        }
    }

    // ---- Markdown ----
    out.push_str(&format!("### {}\n\n", name));

    // Speedup table (ratio mean ± stdev vs baseline).
    out.push_str(&format!(
        "Speedup vs `{}` (per-round ratio, mean ± stdev):\n\n| impl |",
        baseline
    ));
    for &s in SIZES {
        out.push_str(&format!(" {} |", human_size(s)));
    }
    out.push_str("\n|------|");
    for _ in SIZES {
        out.push_str("------|");
    }
    out.push('\n');
    for i in 0..n {
        out.push_str(&format!("| {} |", contenders[i].0));
        for c in &results[i] {
            out.push_str(&format!(" {:.2}±{:.2} |", c.ratio_mean, c.ratio_stdev));
        }
        out.push('\n');
    }
    out.push('\n');

    // Absolute throughput table (GiB/s mean, CV%).
    out.push_str("Absolute GiB/s (mean; CV% in parens — reflects CPU-frequency drift):\n\n| impl |");
    for &s in SIZES {
        out.push_str(&format!(" {} |", human_size(s)));
    }
    out.push_str("\n|------|");
    for _ in SIZES {
        out.push_str("------|");
    }
    out.push('\n');
    for i in 0..n {
        out.push_str(&format!("| {} |", contenders[i].0));
        for c in &results[i] {
            out.push_str(&format!(" {:.2} ({:.0}%) |", c.abs_mean / GIB, 100.0 * c.abs_cv));
        }
        out.push('\n');
    }
    out.push('\n');
}

fn human_size(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{} B", n)
    }
}

macro_rules! ours {
    ($v:expr, $name:expr, $ctor:expr) => {{
        let mut h = $ctor;
        $v.push((
            $name,
            Box::new(move |d: &[u8]| {
                black_box(h.digest(black_box(d)));
            }) as Hasher,
        ));
    }};
}

macro_rules! rc {
    ($v:expr, $name:expr, $ty:ty) => {{
        $v.push((
            $name,
            Box::new(|d: &[u8]| {
                black_box(<$ty as Digest>::digest(black_box(d)));
            }) as Hasher,
        ));
    }};
}

macro_rules! ring_c {
    ($v:expr, $alg:expr) => {{
        $v.push((
            "ring",
            Box::new(|d: &[u8]| {
                black_box(ring::digest::digest($alg, black_box(d)));
            }) as Hasher,
        ));
    }};
}

fn main() {
    let mut out = String::new();

    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_256::Sha256::new());
        ours!(v, "ours_sha_ni", sha_256_ni::Sha256::new());
        rc!(v, "rustcrypto", sha2::Sha256);
        ring_c!(v, &ring::digest::SHA256);
        v.push(("openssl", Box::new(|d: &[u8]| { black_box(openssl::sha::sha256(black_box(d))); })));
        run_group(&mut out, "sha256", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_224::Sha224::new());
        ours!(v, "ours_sha_ni", sha_224_ni::Sha224::new());
        rc!(v, "rustcrypto", sha2::Sha224);
        v.push(("openssl", Box::new(|d: &[u8]| { black_box(openssl::sha::sha224(black_box(d))); })));
        run_group(&mut out, "sha224", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_512::Sha512::new());
        rc!(v, "rustcrypto", sha2::Sha512);
        ring_c!(v, &ring::digest::SHA512);
        v.push(("openssl", Box::new(|d: &[u8]| { black_box(openssl::sha::sha512(black_box(d))); })));
        run_group(&mut out, "sha512", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_384::Sha384::new());
        rc!(v, "rustcrypto", sha2::Sha384);
        ring_c!(v, &ring::digest::SHA384);
        v.push(("openssl", Box::new(|d: &[u8]| { black_box(openssl::sha::sha384(black_box(d))); })));
        run_group(&mut out, "sha384", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_512_256::Sha512_256::new());
        rc!(v, "rustcrypto", sha2::Sha512_256);
        run_group(&mut out, "sha512_256", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_512_224::Sha512_224::new());
        rc!(v, "rustcrypto", sha2::Sha512_224);
        run_group(&mut out, "sha512_224", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_1::Sha1::new());
        ours!(v, "ours_sha_ni", sha_1_ni::Sha1::new());
        rc!(v, "rustcrypto", sha1::Sha1);
        ring_c!(v, &ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
        v.push(("openssl", Box::new(|d: &[u8]| { black_box(openssl::sha::sha1(black_box(d))); })));
        run_group(&mut out, "sha1", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", md_5::Md5::new());
        rc!(v, "rustcrypto", md5::Md5);
        v.push(("openssl", Box::new(|d: &[u8]| {
            black_box(openssl::hash::hash(openssl::hash::MessageDigest::md5(), black_box(d)).unwrap());
        })));
        run_group(&mut out, "md5", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", sha_3::Sha3_256::new());
        rc!(v, "rustcrypto", sha3::Sha3_256);
        v.push(("openssl", Box::new(|d: &[u8]| {
            black_box(openssl::hash::hash(openssl::hash::MessageDigest::sha3_256(), black_box(d)).unwrap());
        })));
        run_group(&mut out, "sha3_256", "rustcrypto", v);
    }
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "ours_portable", blake3_portable::Blake3::new());
        ours!(v, "ours_simd", blake3_simd::Blake3::new());
        v.push(("official_blake3", Box::new(|d: &[u8]| { black_box(blake3::hash(black_box(d))); })));
        run_group(&mut out, "blake3", "official_blake3", v);
    }

    // SHA-256 optimisation-variant study (baseline = our shipped sha_256 crate).
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "current_sha_256", sha_256::Sha256::new());
        ours!(v, "A_naive", sha256_variants::Sha256Naive::new());
        ours!(v, "B_unroll8_rotating", sha256_variants::Sha256Unroll8Rotating::new());
        ours!(v, "C_unroll8_renamed", sha256_variants::Sha256Unroll8Renamed::new());
        ours!(v, "D_renamed_kw", sha256_variants::Sha256RenamedKw::new());
        ours!(v, "F_renamed_unchecked", sha256_variants::Sha256RenamedUnchecked::new());
        ours!(v, "G_renamed_kw_unchecked", sha256_variants::Sha256RenamedKwUnchecked::new());
        rc!(v, "rustcrypto_sha_ni", sha2::Sha256);
        run_group(&mut out, "sha256_variants", "current_sha_256", v);
    }

    // SHA-512 optimisation study: can the scalar tricks beat the scalar libraries?
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "current_sha_512", sha_512::Sha512::new());
        ours!(v, "opt_kw_unchecked", sha512_variants::Sha512Opt::new());
        rc!(v, "rustcrypto", sha2::Sha512);
        ring_c!(v, &ring::digest::SHA512);
        v.push(("openssl", Box::new(|d: &[u8]| { black_box(openssl::sha::sha512(black_box(d))); })));
        run_group(&mut out, "sha512_variants", "rustcrypto", v);
    }

    // SHA-3 optimisation study: fully-unrolled Keccak vs current, RustCrypto, OpenSSL.
    {
        let mut v: Vec<(&str, Hasher)> = Vec::new();
        ours!(v, "current_sha_3", sha_3::Sha3_256::new());
        ours!(v, "opt_unrolled", sha3_variants::Sha3_256Opt::new());
        rc!(v, "rustcrypto", sha3::Sha3_256);
        v.push(("openssl", Box::new(|d: &[u8]| {
            black_box(openssl::hash::hash(openssl::hash::MessageDigest::sha3_256(), black_box(d)).unwrap());
        })));
        run_group(&mut out, "sha3_variants", "current_sha_3", v);
    }

    println!("{}", out);
}
