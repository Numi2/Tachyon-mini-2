//! IPA-style vector Pedersen parameters over Pallas for Tachyon.
//!
//! This module provides only parameter constants and deterministic base
//! derivation utilities. The actual commit/MSM logic and in-circuit gadgets
//! are implemented in later tasks.

use blake2b_simd::Params as Blake2bParams;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{Curve, Group, GroupEncoding};
use group::prime::PrimeCurveAffine;
use pasta_curves::pallas;

/// Maximum degree bound for per-block polynomial (number of roots per block).
pub const DEGREE_N: usize = 4096;
/// Number of polynomial coefficients committed (degree + 1).
pub const NUM_COEFFICIENTS: usize = DEGREE_N + 1;
/// Chunk size for fixed-base tables in MSMs.
pub const CHUNK: usize = 256;
/// Number of chunks to cover all coefficients.
pub const NUM_CHUNKS: usize = (NUM_COEFFICIENTS + CHUNK - 1) / CHUNK;

const H2C_DOMAIN: &[u8] = b"tachyon/ipa:base-derivation";

/// Derive a deterministic Pallas scalar from (chunk, idx).
fn derive_scalar(chunk: u32, idx: u32) -> pallas::Scalar {
    let _buf = [0u8; 8];
    let mut le = [0u8; 8];
    le[..4].copy_from_slice(&chunk.to_le_bytes());
    le[4..].copy_from_slice(&idx.to_le_bytes());

    // Blake2b-512(domain || le(chunk)||le(idx)) as uniform 64 bytes
    let hash = Blake2bParams::new().hash_length(64).personal(H2C_DOMAIN).hash(&le);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(hash.as_bytes());
    <pallas::Scalar as FromUniformBytes<64>>::from_uniform_bytes(&wide)
}

/// Derive a deterministic Pallas base point as s * G, where s = H2C(chunk, idx).
pub fn derive_base(chunk: u32, idx: u32) -> pallas::Affine {
    let s = derive_scalar(chunk, idx);
    (pallas::Affine::generator() * s).to_affine()
}

/// Precompute all bases for NUM_COEFFICIENTS = DEGREE_N + 1.
pub fn derive_all_bases() -> Vec<pallas::Affine> {
    let mut bases = Vec::with_capacity(NUM_COEFFICIENTS);
    let mut remaining = NUM_COEFFICIENTS;
    let mut chunk: u32 = 0;
    while remaining > 0 {
        let take = remaining.min(CHUNK);
        for idx in 0..take {
            bases.push(derive_base(chunk, idx as u32));
        }
        remaining -= take;
        chunk += 1;
    }
    bases
}

/// Derive the first `n` bases G_0..G_{n-1}.
pub fn derive_bases_len(n: usize) -> Vec<pallas::Affine> {
    let mut bases = Vec::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        let chunk = (i / CHUNK) as u32;
        let idx = (i % CHUNK) as u32;
        bases.push(derive_base(chunk, idx));
        i += 1;
    }
    bases
}

/// The distinguished generator G_0 := base for (chunk=0, idx=0).
pub fn g0() -> pallas::Affine { derive_base(0, 0) }

/// Compute vector Pedersen commitment: C = sum_{k=0}^{m-1} coeffs[k] * G_k.
/// Expects `coeffs` in the Pallas scalar field.
pub fn commit_coeffs(coeffs: &[pallas::Scalar]) -> pallas::Affine {
    let m = coeffs.len();
    if m == 0 { return pallas::Point::identity().to_affine(); }
    let bases = derive_bases_len(m);
    msm_pippenger(&bases, coeffs)
}

/// Windowed Pippenger MSM over Pallas: returns sum_i scalars[i] * bases[i].
pub fn msm_pippenger(bases: &[pallas::Affine], scalars: &[pallas::Scalar]) -> pallas::Affine {
    let m = bases.len().min(scalars.len());
    if m == 0 { return pallas::Point::identity().to_affine(); }

    // Heuristic window size based on input size.
    fn optimal_window(n: usize) -> usize {
        match n {
            0..=32 => 3,
            33..=128 => 5,
            129..=512 => 7,
            513..=2048 => 11,
            2049..=8192 => 13,
            _ => 15,
        }
    }

    // Extract w-bit window value from scalar's little-endian bytes at window index `win`.
    #[inline]
    fn window_value(bytes_le: &[u8; 32], win: usize, w: usize) -> u32 {
        let start = win * w;
        let mut acc: u32 = 0;
        for i in 0..w {
            let bit_idx = start + i;
            let byte = bit_idx >> 3; // /8
            if byte >= 32 { break; }
            let bit_in_byte = bit_idx & 7; // %8
            let b = (bytes_le[byte] >> bit_in_byte) & 1;
            acc |= (b as u32) << i;
        }
        acc
    }

    let w = optimal_window(m);
    let num_bits = pallas::Scalar::NUM_BITS as usize; // 255
    let num_windows = (num_bits + w - 1) / w;

    // Precompute LE bytes for scalars once.
    let mut scalars_le = Vec::with_capacity(m);
    for s in &scalars[..m] {
        let repr = <pallas::Scalar as PrimeField>::to_repr(s);
        // Repr for Pasta is little-endian 32 bytes.
        let mut le = [0u8; 32];
        le.copy_from_slice(repr.as_ref());
        scalars_le.push(le);
    }

    let mut acc = pallas::Point::identity();
    // Process windows from high to low.
    for win in (0..num_windows).rev() {
        // Perform w doublings between windows.
        for _ in 0..w { acc = acc.double(); }

        let bucket_len = (1usize << w) - 1;
        let mut buckets = vec![pallas::Point::identity(); bucket_len];

        // Fill buckets.
        for i in 0..m {
            let val = window_value(&scalars_le[i], win, w) as usize;
            if val == 0 { continue; }
            let idx = val - 1; // map 1..2^w-1 -> 0..2^w-2
            buckets[idx] += bases[i].to_curve();
        }

        // Summation by parts: running sum from high bucket to low.
        let mut running = pallas::Point::identity();
        for j in (0..bucket_len).rev() {
            running += buckets[j];
            acc += running;
        }
    }

    acc.to_affine()
}

/// Encode a Pallas point to 32-byte compressed representation.
pub fn encode_point(p: &pallas::Affine) -> [u8; 32] {
    let bytes = p.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}

/// Decode a Pallas point from 32-byte compressed representation.
pub fn decode_point(bytes: &[u8; 32]) -> Option<pallas::Affine> {
    let p = pallas::Affine::from_bytes(bytes);
    Option::<pallas::Affine>::from(p)
}

/// Add two Pallas points.
pub fn add_points(a: &pallas::Affine, b: &pallas::Affine) -> pallas::Affine {
    (a.to_curve() + b.to_curve()).to_affine()
}

/// Scalar-multiply a Pallas point by a Pallas scalar.
pub fn mul_point(a: &pallas::Affine, s: &pallas::Scalar) -> pallas::Affine {
    (a.to_curve() * *s).to_affine()
}

const DS_COEFF_MAP: &[u8] = b"tachyon/coeff-map";

/// Deterministically map a Vesta field element (32-byte repr) into a Pallas scalar
/// using wide reduction of a domain-separated BLAKE2b-512 hash of its canonical bytes.
/// This is only suitable for off-circuit testing and placeholder flows; real circuits
/// must bind the same bit-decomposition consistently.
pub fn map_vesta_scalar_to_pallas(vesta_bytes32: &[u8; 32]) -> pallas::Scalar {
    let hash = Blake2bParams::new().hash_length(64).personal(DS_COEFF_MAP).hash(vesta_bytes32);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(hash.as_bytes());
    <pallas::Scalar as FromUniformBytes<64>>::from_uniform_bytes(&wide)
}

/// Circuit-facing stubs for chunked MSM. Wiring and constraints will be added later.
pub mod circuit {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, Value},
        plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    };

    #[derive(Clone, Debug)]
    pub struct ChunkedMSMParams {
        pub bases: Vec<pallas::Affine>,
        pub chunk: usize,
    }

    impl Default for ChunkedMSMParams {
        fn default() -> Self {
            Self { bases: super::derive_all_bases(), chunk: super::CHUNK }
        }
    }

    /// Off-circuit MSM using pre-derived bases; serves as a reference for the Halo2 gadget.
    pub fn msm_reference(params: &ChunkedMSMParams, scalars: &[pallas::Scalar]) -> pallas::Affine {
        let m = scalars.len().min(params.bases.len());
        let mut acc = pallas::Point::identity();
        for i in 0..m {
            acc += params.bases[i].to_curve() * scalars[i];
        }
        acc.to_affine()
    }

    /// Minimal MSM gadget config: adds and muls to accumulate chunk results.
    #[derive(Clone, Debug)]
    pub struct MsmConfig {
        pub a: Column<Advice>,
        pub b: Column<Advice>,
        pub c: Column<Advice>,
        pub s_mul: Selector,
        pub s_add: Selector,
    }

    impl MsmConfig {
        pub fn configure(meta: &mut ConstraintSystem<pasta_curves::vesta::Scalar>) -> Self {
            let a = meta.advice_column();
            let b = meta.advice_column();
            let c = meta.advice_column();
            let s_mul = meta.selector();
            let s_add = meta.selector();

            meta.create_gate("mul", |meta| {
                let s = meta.query_selector(s_mul);
                let aq = meta.query_advice(a, halo2_proofs::poly::Rotation::cur());
                let bq = meta.query_advice(b, halo2_proofs::poly::Rotation::cur());
                let cq = meta.query_advice(c, halo2_proofs::poly::Rotation::cur());
                vec![s * (aq * bq - cq)]
            });

            meta.create_gate("add", |meta| {
                let s = meta.query_selector(s_add);
                let aq = meta.query_advice(a, halo2_proofs::poly::Rotation::cur());
                let bq = meta.query_advice(b, halo2_proofs::poly::Rotation::cur());
                let cq = meta.query_advice(c, halo2_proofs::poly::Rotation::cur());
                vec![s * (aq + bq - cq)]
            });

            Self { a, b, c, s_mul, s_add }
        }

        /// Stub: wire scalar accumulations for a chunk; elliptic ops are done
        /// off-circuit for now, serving as a placeholder for a fixed-base chip.
        pub fn assign_chunk(
            &self,
            mut layouter: impl Layouter<pasta_curves::vesta::Scalar>,
            scalars_fr: &[pasta_curves::vesta::Scalar],
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "msm-chunk",
                |mut region| {
                    // Accumulate a simple sum as a placeholder; will be replaced with fixed-base MSM.
                    let mut acc = pasta_curves::vesta::Scalar::ZERO;
                    let mut row = 0;
                    for &s in scalars_fr {
                        self.s_add.enable(&mut region, row)?;
                        region.assign_advice(|| "acc", self.a, row, || Value::known(acc))?;
                        region.assign_advice(|| "s", self.b, row, || Value::known(s))?;
                        let new_acc = acc + s;
                        region.assign_advice(|| "acc'", self.c, row, || Value::known(new_acc))?;
                        acc = new_acc;
                        row += 1;
                    }
                    Ok(())
                },
            )
        }
    }

    /// Pairing-free IPA opening proof over the vector commitment C = <c, G>.
    /// Gadget skeleton: O(log n) rounds with challenges from a Blake2b transcript.
    #[derive(Clone, Debug, Default)]
    pub struct IpaProof {
        pub l_vec: Vec<pallas::Affine>,
        pub r_vec: Vec<pallas::Affine>,
        pub a_final: pallas::Scalar,
        pub b_final: pallas::Scalar,
    }

    /// Halo2-facing verifier parameters for inner-product argument.
    #[derive(Clone, Debug, Default)]
    pub struct IpaVerifierParams {
        pub g_bases: Vec<pallas::Affine>,
        pub h_bases: Vec<pallas::Affine>,
        pub u: pallas::Affine,
    }

    /// Verify an IPA opening for value v at evaluation point x against commitment C.
    /// This is a stub for the in-circuit folding logic; no constraints here yet.
    pub fn verify_ipa_opening(
        _params: &IpaVerifierParams,
        _commitment: &pallas::Affine,
        _point_x: &pallas::Scalar,
        _value_v: &pallas::Scalar,
        _proof: &IpaProof,
    ) -> bool {
        // Placeholder: real verifier will perform round-by-round folding using transcript
        // challenges and finally check <g_final, h_final> relation with (a_final, b_final).
        true
    }
}


