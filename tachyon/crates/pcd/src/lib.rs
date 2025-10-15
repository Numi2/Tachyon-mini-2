//! Ragu: PCD + recursion scaffolding for Tachyon.

use serde::{Deserialize, Serialize};

pub mod aggregate;
pub mod block_circuit;
pub mod wallet_step;

/// High-level proving/verification entrypoints (placeholders binding Halo2 APIs).
pub mod api2 {
    use super::{block_circuit::{BlockPolyCircuit, BlockPolyWitness, BlockPolyPublic, prove_block_poly}, wallet_step::{WalletNonMemStepCircuit, WalletStepWitness, WalletStepPublic}};
    use halo2_proofs::dev::MockProver;
    use ff::Field;
    use pasta_curves::vesta::Scalar as FrVesta;

    pub struct Params { pub k: u32 }

    pub fn prove_block(_params: &Params, wit: &BlockPolyWitness) -> anyhow::Result<(BlockPolyPublic, Vec<u8>)> {
        // Compute public summary off-circuit; return stub proof bytes for now.
        let (public, proof) = super::block_circuit::prove_block_poly(wit)?;
        Ok((public, proof))
    }

    pub fn prove_wallet_step(_params: &Params, wit: &WalletStepWitness) -> anyhow::Result<(WalletStepPublic, Vec<u8>)> {
        super::wallet_step::prove_wallet_step(wit)
    }

    pub fn verify_block(params: &Params, _public: &BlockPolyPublic, _proof: &[u8]) -> anyhow::Result<bool> {
        // Use MockProver until real IPA PCS is wired.
        let circuit = BlockPolyCircuit { roots: vec![], coeffs: vec![], r: FrVesta::ONE };
        let prover = MockProver::run(params.k, &circuit, vec![])?;
        Ok(prover.verify().is_ok())
    }

    pub fn verify_wallet_step(params: &Params, _public: &WalletStepPublic, _proof: &[u8]) -> anyhow::Result<bool> {
        // Keep wallet-step on MockProver for now.
        let circuit = WalletNonMemStepCircuit::default();
        let prover = halo2_proofs::dev::MockProver::run(params.k, &circuit, vec![])?;
        Ok(prover.verify().is_ok())
    }
}

/// Authorizing digest (ZIP-244 authorizing-data hash) bound inside PCD.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct AuthorizingDigest(pub [u8; 32]);

/// Tx-level PCD public inputs summary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TxPCDPublic {
    pub range_anchor_min_pos: u64,
    pub range_anchor_max_pos: u64,
    pub range_root_min: [u8; 32],
    pub range_root_max: [u8; 32],
    pub authorizing_digest: AuthorizingDigest,
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub value_commitment: [u8; 32],
    pub fee: u64,
    // Chain-verifiable digests (ZIP-221 leaf extension): allow pruning.
    pub hash_orchard_root: [u8; 32],
    pub hash_nullifier_block: [u8; 32],
    pub hash_commitment_delta: [u8; 32],
}

/// Aggregate-level PCD public inputs summary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct AggPCDPublic {
    pub total_count: u32,
    pub included_txids_digest: [u8; 32],
    pub window_root: [u8; 32],
    // Optionally bind block-level MMR leaf hash if aggregates are per-block.
    pub block_mmr_leaf_hash: [u8; 32],
}

/// High-level interfaces for proving and verifying tx and aggregate PCDs.
pub mod api {
    use super::*;

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
    pub struct TxPCD {
        pub proof: ProofBytes,
        pub public: TxPCDPublic,
    }

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
    pub struct AggPCD {
        pub proof: ProofBytes,
        pub public: AggPCDPublic,
    }

    pub fn prove_tx(_pk: &ProvingKey, _witness: &[u8], public: TxPCDPublic) -> anyhow::Result<TxPCD> {
        Ok(TxPCD { proof: ProofBytes(vec![]), public })
    }

    pub fn verify_tx(_vk: &VerifyingKey, _pcd: &TxPCD) -> anyhow::Result<bool> { Ok(true) }

    pub fn merge(_vk: &VerifyingKey, stamps: &[Tachystamp]) -> anyhow::Result<super::Aggregate> {
        Ok(super::Aggregate { proof: ProofBytes(vec![]), domain: super::DomainSep { is_block: false }, count: stamps.len() as u32 })
    }

    pub fn prove_agg(_pk: &ProvingKey, public: AggPCDPublic, _children: &[TxPCD]) -> anyhow::Result<AggPCD> {
        Ok(AggPCD { proof: ProofBytes(vec![]), public })
    }

    pub fn verify_agg(_vk: &VerifyingKey, _pcd: &AggPCD) -> anyhow::Result<bool> { Ok(true) }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ProofBytes(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct VerifyingKey(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ProvingKey(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DomainSep { pub is_block: bool }

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Tachystamp {
    pub proof: ProofBytes,
    pub domain: DomainSep,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Aggregate {
    pub proof: ProofBytes,
    pub domain: DomainSep,
    pub count: u32,
}

pub fn prove_tx(_pk: &ProvingKey, _witness: &[u8]) -> anyhow::Result<Tachystamp> {
    Ok(Tachystamp { proof: ProofBytes(vec![]), domain: DomainSep { is_block: false } })
}

pub fn merge(_vk: &VerifyingKey, stamps: &[Tachystamp]) -> anyhow::Result<Aggregate> {
    Ok(Aggregate { proof: ProofBytes(vec![]), domain: DomainSep { is_block: false }, count: stamps.len() as u32 })
}

pub fn prove_block(_pk: &ProvingKey, _agg: &Aggregate) -> anyhow::Result<Aggregate> {
    Ok(_agg.clone())
}

pub fn verify(_vk: &VerifyingKey, _proof: &ProofBytes, _domain: &DomainSep) -> anyhow::Result<bool> {
    Ok(true)
}
