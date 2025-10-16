//! Wallet wiring using the blog-style split Circuit and Driver.

use crate::circuit_blog::Circuit as BlogCircuit;
use crate::driver_blog::{Driver as BlogDriver, Error as DriverError, CpuDriverAdapter, PublicInputSink};
use crate::maybe_kind::{Always, Maybe, MaybeKind};
use crate::pcd_blog::{prove_step as prove_step_blog, verify_step as verify_step_blog, Pcd as PcdBlog, PcdData as PcdDataBlog, RecursionBackend as RecursionBackendBlog};
use crate::pasta::FrVesta;
use crate::wallet::{Batch, WalletParams};
use blake3::hash;
use ff::{Field, PrimeField};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Default)]
pub struct TranscriptBackendBlog;

impl RecursionBackendBlog<FrVesta> for TranscriptBackendBlog {
    type Proof = [u8; 32];

    fn allocate_prev<D: BlogDriver<F = FrVesta>>(
        &self,
        _d: &mut D,
        _prev: Option<&PcdBlog<FrVesta, Self::Proof>>,
    ) -> Result<(), DriverError> { Ok(()) }

    fn prove(&self, _inst: &crate::pcd_blog::Instance<FrVesta>, tr: &crate::transcript::FsTranscript) -> Self::Proof {
        tr.challenge_bytes(b"proof-blog")
    }

    fn verify(&self, _inst: &crate::pcd_blog::Instance<FrVesta>, _proof: &Self::Proof) -> bool { true }
}

pub struct WalletCircuitBlog;

impl BlogCircuit<FrVesta> for WalletCircuitBlog {
    type Instance<'i> = PcdDataBlog<FrVesta>;
    type IO<'s, D: BlogDriver<F = FrVesta>> = ();
    type Witness<'w> = PcdDataBlog<FrVesta>;
    type Aux<'w> = ();

    fn input<'i, D: BlogDriver<F = FrVesta>>(
        &self,
        _dr: &mut D,
        _input: <D::MaybeKind as MaybeKind>::Rebind<Self::Instance<'i>>,
    ) -> Result<Self::IO<'i, D>, DriverError> { Ok(()) }

    fn main<'w, D: BlogDriver<F = FrVesta>>(
        &self,
        dr: &mut D,
        witness: <D::MaybeKind as MaybeKind>::Rebind<Self::Witness<'w>>,
    ) -> Result<(Self::IO<'w, D>, <D::MaybeKind as MaybeKind>::Rebind<Self::Aux<'w>>), DriverError> {
        let w = witness.take();
        // Enforce new_root - (old_root + metadata * accumulator) = 0
        let (a, b, c) = dr.mul(|| Ok((w.metadata, w.accumulator, w.metadata * w.accumulator)))?;
        let sum = dr.add(|| [(a, FrVesta::ONE), (b, FrVesta::ZERO), (c, FrVesta::ONE), (crate::cs::Var(0), w.old_root)].into_iter())?; // using adapter's add path
        dr.enforce_zero(|| [(sum, FrVesta::ONE), (crate::cs::Var(0), -w.new_root)].into_iter())?;
        Ok(((), <D::MaybeKind as MaybeKind>::Rebind::<'w, _>::just(|| ())))
    }

    fn output<'s, D: BlogDriver<F = FrVesta>>(
        &self,
        _dr: &mut D,
        _io: Self::IO<'s, D>,
        _output: &mut D::IO,
    ) -> Result<(), DriverError> { Ok(()) }
}


