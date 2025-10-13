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


