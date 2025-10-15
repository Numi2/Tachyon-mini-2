//! Ragu: PCD + recursion scaffolding for Tachyon.

use serde::{Deserialize, Serialize};

pub mod aggregate;

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
