//! ragu-lite: minimal, functioning scaffolding for Ragu-style PCD over the Pasta cycle.
//! Includes a prototype wallet that carries its own recursive state proof.

pub mod pasta;
pub mod maybe;
pub mod cs;
pub mod driver;
pub mod accum;
pub mod pcd;
pub mod transcript;
pub mod wallet;

#[cfg(feature = "blog_api")]
pub mod maybe_kind;
#[cfg(feature = "blog_api")]
pub mod driver_blog;
#[cfg(feature = "blog_api")]
pub mod circuit_blog;
#[cfg(feature = "blog_api")]
pub mod pcd_blog;
#[cfg(feature = "blog_api")]
pub mod wallet_blog;

pub use accum::{Accumulator, SplitAccumulator};
pub use cs::{Constraint, ConstraintSystem, LinComb, Var};
pub use driver::{Circuit, CpuDriver, Driver, Instance, SynthesisError};
pub use maybe::Maybe;
pub use pcd::{prove_step, verify_step, Pcd, PcdData, RecursionBackend, TranscriptBackend};
pub use pasta::{FrPallas, FrVesta};
pub use wallet::{
    Batch, Note, TachyObj, Wallet, WalletCircuit, WalletParams,
};
pub use transcript::FsTranscript;

#[cfg(feature = "blog_api")]
pub use driver_blog as blog_driver;
#[cfg(feature = "blog_api")]
pub use circuit_blog as blog_circuit;
#[cfg(feature = "blog_api")]
pub use pcd_blog as blog_pcd;
#[cfg(feature = "blog_api")]
pub use wallet_blog as blog_wallet;


