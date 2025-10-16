//! Blog-style Driver abstraction with wire type `W`, `MaybeKind`, and `IO` sink.

use crate::cs::{ConstraintSystem, LinComb, Var};
use crate::maybe_kind::{Always, AlwaysKind, Maybe, MaybeKind};
use ff::PrimeField;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("synthesis error")]
    Synthesis,
}

/// IO sink used by `Circuit::output` to collect public inputs in driver-defined order.
pub trait Sink<D: Driver>: Default {
    fn push(&mut self, d: &mut D, w: D::W);
}

/// A simple sink backed by the driver's own `input_public` machinery.
#[derive(Default)]
pub struct PublicInputSink;

impl<F: PrimeField, D: Driver<F = F, W = Var>> Sink<D> for PublicInputSink {
    fn push(&mut self, d: &mut D, w: D::W) {
        // Interpret w as a value and expose it as a public input wire.
        // CpuDriver adapter will handle the reification.
        d.expose_public(w);
    }
}

/// Blog-style Driver trait closely following the post.
pub trait Driver {
    type F: PrimeField;
    type W: Clone;
    const ONE: Self::W;
    type MaybeKind: MaybeKind;
    type IO: Sink<Self>;

    fn cs(&mut self) -> &mut ConstraintSystem<Self::F>;

    fn mul(
        &mut self,
        values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), Error>,
    ) -> Result<(Self::W, Self::W, Self::W), Error>;

    fn add<L: IntoIterator<Item = (Self::W, Self::F)>>(
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<Self::W, Error>;

    fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>(
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<(), Error>;

    fn expose_public(&mut self, w: Self::W);
}

/// Adapter over existing CpuDriver to implement the blog Driver.
pub struct CpuDriverAdapter<F: PrimeField> {
    inner: crate::driver::CpuDriver<F>,
}

impl<F: PrimeField> CpuDriverAdapter<F> {
    pub fn new() -> Self { Self { inner: crate::driver::CpuDriver::new() } }
    fn as_var(w: Var) -> Var { w }
}

impl<F: PrimeField> Driver for CpuDriverAdapter<F> {
    type F = F;
    type W = Var;
    const ONE: Self::W = Var(0); // placeholder; not used as a constant wire directly
    type MaybeKind = AlwaysKind;
    type IO = PublicInputSink;

    fn cs(&mut self) -> &mut ConstraintSystem<Self::F> { self.inner.cs() }

    fn mul(
        &mut self,
        values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), Error>,
    ) -> Result<(Self::W, Self::W, Self::W), Error> {
        let (a, b, c) = values()?;
        let va = self.inner.witness(a);
        let vb = self.inner.witness(b);
        let vc = self.inner.witness(c);
        self.inner.cs().r1cs(
            LinComb { terms: vec![(va, F::ONE)], constant: F::ZERO },
            LinComb { terms: vec![(vb, F::ONE)], constant: F::ZERO },
            LinComb { terms: vec![(vc, F::ONE)], constant: F::ZERO },
        );
        Ok((va, vb, vc))
    }

    fn add<L: IntoIterator<Item = (Self::W, Self::F)>>(
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<Self::W, Error> {
        // Convert LC into a new witness wire equal to the LC value.
        // Evaluate using inner values and enforce zero accordingly.
        let mut terms = Vec::new();
        let mut constant = F::ZERO;
        for (w, c) in lc() { terms.push((w, c)); }

        // Evaluate value for witness: sum c_i * v_i + constant
        let mut acc = constant;
        for (v, c) in &terms {
            acc += self.inner.value(*v) * *c;
        }
        let out = self.inner.witness(acc);
        let lc = LinComb { terms: terms.into_iter().chain(core::iter::once((out, -F::ONE))).collect(), constant };
        self.inner.enforce_zero(lc);
        Ok(out)
    }

    fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>(
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<(), Error> {
        let mut combo = LinComb::<F>::zero();
        for (w, c) in lc() { combo = combo.add_term(w, c); }
        self.inner.enforce_zero(combo);
        Ok(())
    }

    fn expose_public(&mut self, w: Self::W) {
        let v = self.inner.value(w);
        let _ = self.inner.input_public(v);
    }
}


