//! PCD container and mock recursion backend.

use crate::driver::{Circuit, Driver, Instance, SynthesisError};
use crate::transcript::FsTranscript;
use ff::PrimeField;

/// Payload carried by the PCD proof.
#[derive(Clone, Debug)]
pub struct PcdData<F: PrimeField> {
    pub old_root: F,
    pub new_root: F,
    pub metadata: F,
    pub accumulator: F,
}

/// Generic "proof" that carries data plus a transcript commitment.
/// This is a placeholder. Backend controls how `inner` is interpreted.
#[derive(Clone, Debug)]
pub struct Pcd<F: PrimeField, Inner> {
    pub data: PcdData<F>,
    pub instance: Instance<F>,
    pub inner: Inner,
    pub depth: u64,
}

pub trait RecursionBackend<F: PrimeField> {
    type Proof: Clone + Send + Sync + 'static;

    /// Verify previous proof inside the circuit by exposing its instance fields.
    fn allocate_prev<D: Driver<F>>(
        &self,
        d: &mut D,
        prev: Option<&Pcd<F, Self::Proof>>,
    ) -> Result<(), SynthesisError>;

    /// Produce a new outer proof from the synthesized instance.
    fn prove(&self, inst: &Instance<F>, tr: &FsTranscript) -> Self::Proof;

    /// Verify a proof against an instance.
    fn verify(&self, inst: &Instance<F>, proof: &Self::Proof) -> bool;
}

/// A simple transcript-only backend. Not a SNARK. Useful to exercise the API.
#[derive(Clone, Default)]
pub struct TranscriptBackend;

impl<F: PrimeField> RecursionBackend<F> for TranscriptBackend {
    type Proof = [u8; 32];

    fn allocate_prev<D: Driver<F>>(
        &self,
        _d: &mut D,
        _prev: Option<&Pcd<F, Self::Proof>>,
    ) -> Result<(), SynthesisError> {
        // Intentionally no constraints. Real backend would in-circuit-verify prev.inner.
        Ok(())
    }

    fn prove(&self, inst: &Instance<F>, tr: &FsTranscript) -> Self::Proof {
        let mut t = FsTranscript::new(b"ragu-lite/pcd");
        for x in &inst.inputs {
            t.absorb_field(x);
        }
        t.absorb(&tr.challenge_bytes(b"context"));
        t.challenge_bytes(b"proof")
    }

    fn verify(&self, inst: &Instance<F>, proof: &Self::Proof) -> bool {
        let recomputed = {
            let mut t = FsTranscript::new(b"ragu-lite/pcd");
            for x in &inst.inputs {
                t.absorb_field(x);
            }
            t.absorb(&FsTranscript::default().challenge_bytes(b"context"));
            t.challenge_bytes(b"proof")
        };
        &recomputed == proof
    }
}

/// Synthesize a state transition step and wrap it as PCD.
/// Input → main → output with `add`, `mul`, and `enforce_zero` primitives only.
pub fn prove_step<F, C, B, D>(
    backend: &B,
    circuit: &C,
    mut driver: D,
    prev: Option<&Pcd<F, B::Proof>>,
    data: PcdData<F>,
) -> Result<Pcd<F, B::Proof>, SynthesisError>
where
    F: PrimeField,
    C: Circuit<F, Input = PcdData<F>, Output = ()>,
    B: RecursionBackend<F>,
    D: Driver<F, Var = crate::cs::Var>,
{
    // Allocate previous proof's instance in-circuit (mocked here).
    backend.allocate_prev(&mut driver, prev)?;

    // Public inputs are circuit-defined: old_root, new_root, metadata, accumulator.
    let inp_old = driver.input_public(data.old_root);
    let inp_new = driver.input_public(data.new_root);
    let inp_meta = driver.input_public(data.metadata);
    let inp_acc = driver.input_public(data.accumulator);

    // Example transition rule: enforce new_root = old_root + metadata * accumulator.
    let prod = driver.mul(inp_meta, inp_acc);
    let rhs = driver.add(inp_old, prod);
    // new_root - rhs = 0
    driver.enforce_zero(
        crate::cs::LinComb::from_var(inp_new).add_term(rhs, -F::ONE)
    );

    // Let the user circuit add more rules if desired.
    circuit.synthesize(&mut driver, data.clone());

    let instance = driver.instance();
    let mut tr = FsTranscript::new(b"ragu-lite/step");
    tr.absorb(&u64::to_le_bytes(prev.map(|p| p.depth).unwrap_or(0)));
    let proof = backend.prove(&instance, &tr);

    Ok(Pcd {
        data,
        instance,
        inner: proof,
        depth: prev.map(|p| p.depth + 1).unwrap_or(1),
    })
}

pub fn verify_step<F, B: RecursionBackend<F>>(
    backend: &B,
    p: &Pcd<F, B::Proof>,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
{
    if backend.verify(&p.instance, &p.inner) { Ok(()) } else { Err(SynthesisError::Verification) }
}


