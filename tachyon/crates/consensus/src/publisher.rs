//! Block publisher helpers: build per-block polynomial commitment and proof.

use accum::{ipa, poly, poseidon};
use primitives::digest::tachygram_to_fr as tg_to_fr;
use crate::accum_record::{BlockAccumRecord, PallasPointBytes};
use pcd::{block_circuit::BlockPolyWitness, api2};
use pasta_curves::pallas;
use ff::PrimeField;

/// Build a BlockAccumRecord from prior accumulator A_i and block tachygrams.
/// Uses FFT for large batches and falls back to simple method otherwise.
pub fn build_block_record(a_i: &PallasPointBytes, grams: &[[u8; 32]]) -> anyhow::Result<BlockAccumRecord> {
    // Map grams → Fr(Vesta), sort and dedup
    let mut roots: Vec<_> = grams.iter().map(tg_to_fr).collect();
    roots.sort();
    roots.dedup();

    // Compute coefficients via FFT when large, else divide-and-conquer
    let coeffs = if roots.len() >= 64 {
        poly::roots_to_coeffs_fft(&roots)
    } else {
        poly::roots_to_coeffs_parallel(&roots)
    };

    // Map coeffs (FrVesta) → Pallas scalars and commit
    let scalars: Vec<pallas::Scalar> = coeffs.iter().map(|x| {
        let xb = ff::PrimeField::to_repr(x);
        let mut b32 = [0u8; 32];
        b32.copy_from_slice(xb.as_ref());
        ipa::map_vesta_scalar_to_pallas(&b32)
    }).collect();
    let p_i_aff = ipa::commit_coeffs(&scalars);
    let p_i_bytes = PallasPointBytes(ipa::encode_point(&p_i_aff));

    // Build circuit witness and produce proof (mock for now)
    let a_i_aff = ipa::decode_point(&a_i.0).unwrap_or(ipa::g0());
    let wit = BlockPolyWitness { roots, coeffs, p_i: p_i_aff, a_i: a_i_aff };
    let (public, proof) = api2::prove_block(&api2::Params { k: 18 }, &wit)?;
    // Public includes p_i,a_i,a_next bytes; recompute h_i for record
    let h_i = poseidon::hash_A_h(&public.a_i_bytes, &public.p_i_bytes);
    Ok(BlockAccumRecord { p_i: p_i_bytes, h_i, a_next: PallasPointBytes(public.a_next_bytes), proof })
}


