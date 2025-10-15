//! Consensus record for per-block accumulator publication.

use serde::{Deserialize, Serialize};
use accum::{ipa, poseidon};
use group::prime::PrimeCurveAffine;
use group::Curve;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct PallasPointBytes(pub [u8; 32]);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct BlockAccumRecord {
    /// Polynomial commitment for block i (Pallas G1 compressed bytes).
    pub p_i: PallasPointBytes,
    /// Domain-separated hash h_i = H_A(A_i, P_i).
    pub h_i: [u8; 32],
    /// Accumulator state A_{i+1} (Pallas G1 compressed bytes).
    pub a_next: PallasPointBytes,
    /// Halo2 proof bytes attesting block polynomial identity and accumulator step.
    pub proof: Vec<u8>,
}

impl BlockAccumRecord {
    /// Publisher helper: compute h_i and A_{i+1} from (A_i, P_i) and proof bytes.
    pub fn from_ai_pi(a_i: &PallasPointBytes, p_i: &PallasPointBytes, proof: Vec<u8>) -> Self {
        let h_i = poseidon::hash_A_h(&a_i.0, &p_i.0);
        // Map h_i to Pallas scalar and compute A_{i+1} = [h_i]A_i + P_i
        let a_i_aff = ipa::decode_point(&a_i.0).unwrap_or(ipa::g0());
        let p_i_aff = ipa::decode_point(&p_i.0).unwrap_or(ipa::g0());
        let h_scalar = ipa::map_vesta_scalar_to_pallas(&h_i);
        let a_next_aff = (a_i_aff.to_curve() * h_scalar + p_i_aff.to_curve()).to_affine();
        let a_next = PallasPointBytes(ipa::encode_point(&a_next_aff));
        Self { p_i: *p_i, h_i, a_next, proof }
    }

    /// Verifier helper: check that (h_i, a_next) are consistent with (A_i, P_i).
    /// This does not verify the Halo2 proof; call the block-circuit verifier separately.
    pub fn verify_step(&self, a_i: &PallasPointBytes) -> bool {
        let a_i_aff = match ipa::decode_point(&a_i.0) { Some(p) => p, None => return false };
        let p_i_aff = match ipa::decode_point(&self.p_i.0) { Some(p) => p, None => return false };
        let expected_h = poseidon::hash_A_h(&a_i.0, &self.p_i.0);
        if expected_h != self.h_i { return false; }
        let h_scalar = ipa::map_vesta_scalar_to_pallas(&self.h_i);
        let a_next = (a_i_aff.to_curve() * h_scalar + p_i_aff.to_curve()).to_affine();
        ipa::encode_point(&a_next) == self.a_next.0
    }
}


