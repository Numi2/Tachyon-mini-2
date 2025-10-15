//! WalletNonMemStepCircuit skeleton: updates A/S and enforces alpha != 0.

use accum::{ipa, poseidon};
use halo2_proofs::{plonk::{Circuit, ConstraintSystem, Error}};
use pasta_curves::{pallas, vesta::Scalar as FrVesta};
use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;

#[derive(Clone, Debug, Default)]
pub struct WalletStepWitness {
    pub v: FrVesta,
    pub alpha_i: FrVesta,
    pub alpha_inv: FrVesta,
    pub p_i: pallas::Affine,
    pub s_i: pallas::Affine,
    pub a_i: pallas::Affine,
}

#[derive(Clone, Debug, Default)]
pub struct WalletStepPublic {
    pub a_i_bytes: [u8; 32],
    pub a_next_bytes: [u8; 32],
    pub s_next_bytes: [u8; 32],
}

pub fn prove_wallet_step(w: &WalletStepWitness) -> anyhow::Result<(WalletStepPublic, Vec<u8>)> {
    // Check alpha * alpha_inv = 1 (off-circuit sanity; circuit will enforce).
    if w.alpha_i * w.alpha_inv != FrVesta::ONE {
        anyhow::bail!("alpha inverse mismatch");
    }

    // Compute P_i' = P_i - [alpha_i] G_0.
    let g0 = ipa::g0();
    let alpha_bytes = {
        let repr = ff::PrimeField::to_repr(&w.alpha_i);
        let mut b32 = [0u8; 32];
        b32.copy_from_slice(repr.as_ref());
        b32
    };
    let alpha_pallas = ipa::map_vesta_scalar_to_pallas(&alpha_bytes);
    let p_prime = (w.p_i.to_curve() + g0.to_curve() * (-alpha_pallas)).to_affine();

    // Domain hashes.
    let p_i_bytes = ipa::encode_point(&w.p_i);
    let a_i_bytes = ipa::encode_point(&w.a_i);
    let s_i_bytes = ipa::encode_point(&w.s_i);
    let p_prime_bytes = ipa::encode_point(&p_prime);
    let h_i_bytes = poseidon::hash_A_h(&a_i_bytes, &p_i_bytes);
    let h_i_prime_bytes = poseidon::hash_S_h(&s_i_bytes, &p_prime_bytes);

    // Convert hashes to scalars (best-effort for the stub).
    let h_i = ipa::map_vesta_scalar_to_pallas(&h_i_bytes);
    let h_i_prime = ipa::map_vesta_scalar_to_pallas(&h_i_prime_bytes);

    // Update states.
    let a_next = (w.a_i.to_curve() * h_i + w.p_i.to_curve()).to_affine();
    let s_next = (w.s_i.to_curve() * h_i_prime + p_prime.to_curve()).to_affine();

    Ok((
        WalletStepPublic {
            a_i_bytes,
            a_next_bytes: ipa::encode_point(&a_next),
            s_next_bytes: ipa::encode_point(&s_next),
        },
        vec![],
    ))
}

#[derive(Clone, Debug, Default)]
pub struct WalletNonMemStepCircuit;

impl Circuit<pasta_curves::vesta::Scalar> for WalletNonMemStepCircuit {
    type Config = ();
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self }

    fn configure(_meta: &mut ConstraintSystem<pasta_curves::vesta::Scalar>) -> Self::Config { () }

    fn synthesize(&self, _config: Self::Config, _layouter: impl halo2_proofs::circuit::Layouter<pasta_curves::vesta::Scalar>) -> Result<(), Error> {
        Ok(())
    }
}


