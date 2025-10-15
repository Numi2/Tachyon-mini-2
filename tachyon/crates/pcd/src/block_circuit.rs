//! Halo2 BlockPolyCircuit over Vesta field with Pallas commitments.

use accum::{ipa, poseidon};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
};
use pasta_curves::{pallas, vesta::Scalar as FrVesta};
use accum::ipa::circuit::MsmConfig;
use ff::Field;
use group::Curve;
use group::prime::PrimeCurveAffine;
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug, Default)]
pub struct BlockPolyWitness {
    /// Roots a_{ij} mapped to Fr(Vesta), sorted and deduped, len ≤ 4096.
    pub roots: Vec<FrVesta>,
    /// Polynomial coefficients c_k in increasing degree order (len = roots+1).
    pub coeffs: Vec<FrVesta>,
    /// Committed P_i point (redundant with coeffs; used for cross-checks).
    pub p_i: pallas::Affine,
    /// Previous accumulator A_i (Pallas G1).
    pub a_i: pallas::Affine,
}

#[derive(Clone, Debug, Default)]
pub struct BlockPolyPublic {
    pub p_i_bytes: [u8; 32],
    pub a_i_bytes: [u8; 32],
    pub a_next_bytes: [u8; 32],
}

/// Off-circuit prover skeleton: computes public inputs and returns dummy proof bytes.
pub fn prove_block_poly(w: &BlockPolyWitness) -> anyhow::Result<(BlockPolyPublic, Vec<u8>)> {
    // Encode public points.
    let p_i_bytes = ipa::encode_point(&w.p_i);
    let a_i_bytes = ipa::encode_point(&w.a_i);

    // Off-circuit binding: check P_i equals Commit(coeffs) with chunked MSM mapping.
    let coeffs_pallas: Vec<pallas::Scalar> = w.coeffs.iter().map(|x| {
        let xb = ff::PrimeField::to_repr(x);
        let mut b32 = [0u8; 32];
        b32.copy_from_slice(xb.as_ref());
        ipa::map_vesta_scalar_to_pallas(&b32)
    }).collect();
    let p_i_ref = ipa::commit_coeffs(&coeffs_pallas);
    if ipa::encode_point(&p_i_ref) != p_i_bytes { anyhow::bail!("commitment mismatch for P_i"); }

    // Derive r and evaluate both sides off-circuit for a quick sanity check.
    let r_bytes = poseidon::derive_block_r(&p_i_bytes, &a_i_bytes);
    let r = {
        // Use wide reduction to ensure uniform field mapping.
        use ff::FromUniformBytes;
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&r_bytes);
        wide[32..].copy_from_slice(&r_bytes);
        <FrVesta as FromUniformBytes<64>>::from_uniform_bytes(&wide)
    };
        let lhs = w.roots.iter().fold(<FrVesta as ff::Field>::ONE, |acc, a| acc * (r - *a));
    let rhs = accum::poly::eval_horner(&w.coeffs, r);
    if lhs != rhs { anyhow::bail!("polynomial identity failed off-circuit"); }

    // Compute h_i and A_{i+1} off-circuit (bytes-level hash; scalar multiply using Pallas).
    let h_i_bytes = poseidon::hash_A_h(&a_i_bytes, &p_i_bytes);
    let h_i = ipa::map_vesta_scalar_to_pallas(&h_i_bytes);
    let a_next = w.a_i.to_curve() * h_i + w.p_i.to_curve();
    let a_next_bytes = ipa::encode_point(&a_next.to_affine());

    Ok((BlockPolyPublic { p_i_bytes, a_i_bytes, a_next_bytes }, vec![]))
}

// Minimal Halo2 circuit scaffolding: exposes the same public inputs layout.
#[derive(Clone, Debug)]
pub struct BlockPolyCircuit {
    pub roots: Vec<FrVesta>,
    pub coeffs: Vec<FrVesta>,
    pub r: FrVesta,
}

#[derive(Clone, Debug)]
pub struct BlockPolyConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    s_mul: Selector,
    s_add: Selector,
    s_eq: Selector,
    msm: MsmConfig,
}

impl BlockPolyCircuit {
    pub fn from_witness(w: &BlockPolyWitness) -> Self {
        let p_i_bytes = ipa::encode_point(&w.p_i);
        let a_i_bytes = ipa::encode_point(&w.a_i);
        let r_bytes = poseidon::derive_block_r(&p_i_bytes, &a_i_bytes);
        use ff::FromUniformBytes;
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&r_bytes);
        wide[32..].copy_from_slice(&r_bytes);
        let r = <FrVesta as FromUniformBytes<64>>::from_uniform_bytes(&wide);
        Self { roots: w.roots.clone(), coeffs: w.coeffs.clone(), r }
    }
}

impl Circuit<FrVesta> for BlockPolyCircuit {
    type Config = BlockPolyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self { roots: vec![], coeffs: vec![], r: <FrVesta as ff::Field>::ONE } }

    fn configure(meta: &mut ConstraintSystem<FrVesta>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();
        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_eq = meta.selector();
        let msm = MsmConfig::configure(meta);

        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a_q = meta.query_advice(a, Rotation::cur());
            let b_q = meta.query_advice(b, Rotation::cur());
            let c_q = meta.query_advice(c, Rotation::cur());
            vec![s * (a_q * b_q - c_q)]
        });

        meta.create_gate("add", |meta| {
            let s = meta.query_selector(s_add);
            let a_q = meta.query_advice(a, Rotation::cur());
            let b_q = meta.query_advice(b, Rotation::cur());
            let c_q = meta.query_advice(c, Rotation::cur());
            vec![s * (a_q + b_q - c_q)]
        });

        meta.create_gate("eq", |meta| {
            let s = meta.query_selector(s_eq);
            let c_q = meta.query_advice(c, Rotation::cur());
            let d_q = meta.query_advice(d, Rotation::cur());
            vec![s * (c_q - d_q)]
        });

        BlockPolyConfig { a, b, c, d, s_mul, s_add, s_eq, msm }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<FrVesta>) -> Result<(), Error> {
        // Compute lhs = ∏(r - a_j) and rhs = Horner(coeffs, r)
        let r = self.r;
        let roots = self.roots.clone();
        let coeffs = self.coeffs.clone();

        // Product chain
        let lhs_val = roots.iter().fold(FrVesta::ONE, |acc, a| acc * (r - *a));
        layouter.assign_region(
            || "product",
            |mut region| {
                // initialize acc = 1
                let row0 = 0;
                let one = Value::known(<FrVesta as ff::Field>::ONE);
                region.assign_advice(|| "acc0", cfg.c, row0, || one)?;
                let mut cur_row = 1;
                let mut acc = <FrVesta as ff::Field>::ONE;
                for a_root in roots.iter() {
                    let a_val = Value::known(acc);
                    let b_val = Value::known(r - *a_root);
                    let c_val = Value::known(acc * (r - *a_root));
                    cfg.s_mul.enable(&mut region, cur_row)?;
                    region.assign_advice(|| "a", cfg.a, cur_row, || a_val)?;
                    region.assign_advice(|| "b", cfg.b, cur_row, || b_val)?;
                    region.assign_advice(|| "c", cfg.c, cur_row, || c_val)?;
                    acc = acc * (r - *a_root);
                    cur_row += 1;
                }
                // store final lhs in c at cur_row
                region.assign_advice(|| "lhs", cfg.c, cur_row, || Value::known(acc))?;
                Ok(())
            },
        )?;

        // Horner evaluation
        let rhs_val = {
            let mut acc = <FrVesta as ff::Field>::ZERO;
            for &c in coeffs.iter().rev() { acc = acc * r + c; }
            acc
        };
        layouter.assign_region(
            || "horner",
            |mut region| {
                // compute acc = acc * r + c across rows
                let mut acc = <FrVesta as ff::Field>::ZERO;
                let mut row = 0;
                for &coef in coeffs.iter().rev() {
                    // t = acc * r
                    cfg.s_mul.enable(&mut region, row)?;
                    region.assign_advice(|| "acc", cfg.a, row, || Value::known(acc))?;
                    region.assign_advice(|| "r", cfg.b, row, || Value::known(r))?;
                    region.assign_advice(|| "t", cfg.c, row, || Value::known(acc * r))?;
                    // acc' = t + coef
                    cfg.s_add.enable(&mut region, row + 1)?;
                    region.assign_advice(|| "t", cfg.a, row + 1, || Value::known(acc * r))?;
                    region.assign_advice(|| "coef", cfg.b, row + 1, || Value::known(coef))?;
                    let new_acc = acc * r + coef;
                    region.assign_advice(|| "acc'", cfg.c, row + 1, || Value::known(new_acc))?;
                    acc = new_acc;
                    row += 2;
                }
                // store rhs in d at row
                region.assign_advice(|| "rhs", cfg.d, row, || Value::known(acc))?;
                Ok(())
            },
        )?;

        // Enforce lhs == rhs via equality gate on a final row
        layouter.assign_region(
            || "eq",
            |mut region| {
                cfg.s_eq.enable(&mut region, 0)?;
                region.assign_advice(|| "lhs", cfg.c, 0, || Value::known(lhs_val))?;
                region.assign_advice(|| "rhs", cfg.d, 0, || Value::known(rhs_val))?;
                Ok(())
            },
        )?;

        // Wire a placeholder chunked MSM region to bind coefficients into the circuit
        // using a simple accumulation placeholder. This will be replaced by a
        // fixed-base MSM using an ECC chip.
        cfg.msm.assign_chunk(layouter, &self.coeffs)?;

        Ok(())
    }
}


