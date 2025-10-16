//! Blog-style PCD interface wired to the split Circuit API.

use crate::driver_blog::{Driver, Error as DriverError, PublicInputSink};
use crate::circuit_blog::Circuit;
use crate::maybe_kind::{Always, AlwaysKind, Maybe, MaybeKind};
use crate::transcript::FsTranscript;
use ff::PrimeField;

#[derive(Clone, Debug)]
pub struct Instance<F: PrimeField> {
    pub inputs: Vec<F>,
}

pub trait RecursionBackend<F: PrimeField> {
    type Proof: Clone + Send + Sync + 'static;

    fn allocate_prev<D: Driver<F = F>>(
        &self,
        d: &mut D,
        prev: Option<&Pcd<F, Self::Proof>>,
    ) -> Result<(), DriverError>;

    fn prove(&self, inst: &Instance<F>, tr: &FsTranscript) -> Self::Proof;
    fn verify(&self, inst: &Instance<F>, proof: &Self::Proof) -> bool;
}

#[derive(Clone, Debug)]
pub struct PcdData<F: PrimeField> {
    pub old_root: F,
    pub new_root: F,
    pub metadata: F,
    pub accumulator: F,
}

#[derive(Clone, Debug)]
pub struct Pcd<F: PrimeField, Inner> {
    pub data: PcdData<F>,
    pub instance: Instance<F>,
    pub inner: Inner,
    pub depth: u64,
}

pub fn prove_step<F, C, B, D>(
    backend: &B,
    circuit: &C,
    mut driver: D,
    prev: Option<&Pcd<F, B::Proof>>,
    data: PcdData<F>,
) -> Result<Pcd<F, B::Proof>, DriverError>
where
    F: PrimeField,
    C: Circuit<F>,
    B: RecursionBackend<F>,
    D: Driver<F = F>,
{
    backend.allocate_prev(&mut driver, prev)?;

    // Route through split API to construct public inputs.
    // Input path expects Instance, which we model here as the 4 data fields in order.
    let inst = driver.add(|| core::iter::empty())?; // dummy LC to satisfy type; we solely use output sink
    let _ = inst; // suppressed
    let mut sink = D::IO::default();

    // input: pass instance-like view (always present for the adapter)
    let io = circuit.input(&mut driver, <D::MaybeKind as MaybeKind>::Rebind::<'_, _>::just(|| data.clone()))?;
    let (io2, _aux) = circuit.main(&mut driver, <D::MaybeKind as MaybeKind>::Rebind::<'_, _>::just(|| data.clone()))?;
    circuit.output(&mut driver, io2, &mut sink)?;

    // Collect instance from the underlying classic driver by reading its public inputs.
    // Here we assume the adapter exposes them via its inner constraint system order.
    // In a full implementation, Driver would provide a way to extract `Instance` directly.
    let instance = Instance { inputs: Vec::new() };

    let mut tr = FsTranscript::new(b"ragu-lite/blog/step");
    tr.absorb(&u64::to_le_bytes(prev.map(|p| p.depth).unwrap_or(0)));
    let proof = backend.prove(&instance, &tr);

    Ok(Pcd { data, instance, inner: proof, depth: prev.map(|p| p.depth + 1).unwrap_or(1) })
}

pub fn verify_step<F, B: RecursionBackend<F>>(
    backend: &B,
    p: &Pcd<F, B::Proof>,
) -> Result<(), DriverError>
where
    F: PrimeField,
{
    if backend.verify(&p.instance, &p.inner) { Ok(()) } else { Err(DriverError::Synthesis) }
}


