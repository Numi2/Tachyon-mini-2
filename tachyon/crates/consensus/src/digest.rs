//! Per-block digests and MMR leaf (ZIP-221 extension).

use blake2b_simd::Params as Blake2bParams;
use serde::{Deserialize, Serialize};

/// BLAKE2b-256 digest of the latest Orchard commitment tree root.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct OrchardRootDigest(pub [u8; 32]);

/// BLAKE2b-256 digest of the ordered per-block nullifier vector.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct NullifierBlockDigest(pub [u8; 32]);

/// BLAKE2b-256 digest of the per-block commitment-tree delta (ordered adds).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct CommitmentDeltaDigest(pub [u8; 32]);

/// MMR leaf extension committed in chain history.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct BlockMMRLeaf {
    pub orchard_root_digest: OrchardRootDigest,
    pub nullifier_block_digest: NullifierBlockDigest,
    pub commitment_delta_digest: CommitmentDeltaDigest,
}

const DS_ORCH_ROOT_V1: &[u8; 16] = b"orch.root.v1\0\0\0\0"; // 12 + 4 = 16
const DS_NF_BLOCK_V1: &[u8; 16] = b"nf.block.v1\0\0\0\0\0"; // 11 + 5 = 16
const DS_CM_DELTA_V1: &[u8; 16] = b"cm.delta.v1\0\0\0\0\0"; // 11 + 5 = 16
const DS_MMR_LEAF_V1: &[u8; 16] = b"mmr.leaf.v1\0\0\0\0\0"; // 11 + 5 = 16
const DS_TG_UNIFIED_BLOCK_V1: &[u8; 16] = b"tg.unified.blk\0\0"; // 14 + 2 = 16

/// Compute BLAKE2b-256 digest of the current Orchard root (domain-separated).
pub fn compute_orchard_root_digest(root: &[u8; 32]) -> OrchardRootDigest {
    let hash = Blake2bParams::new().hash_length(32).personal(DS_ORCH_ROOT_V1).hash(root);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    OrchardRootDigest(out)
}

/// Compute BLAKE2b-256 digest of the ordered per-block nullifier vector.
pub fn compute_nullifier_block_digest(nullifiers: &[[u8; 32]]) -> NullifierBlockDigest {
    let mut buf = Vec::with_capacity(nullifiers.len() * 32);
    for nf in nullifiers { buf.extend_from_slice(nf); }
    let hash = Blake2bParams::new().hash_length(32).personal(DS_NF_BLOCK_V1).hash(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    NullifierBlockDigest(out)
}

/// Compute BLAKE2b-256 digest of the ordered per-block commitment additions.
pub fn compute_commitment_delta_digest(commitments: &[[u8; 32]]) -> CommitmentDeltaDigest {
    let mut buf = Vec::with_capacity(commitments.len() * 32);
    for cm in commitments { buf.extend_from_slice(cm); }
    let hash = Blake2bParams::new().hash_length(32).personal(DS_CM_DELTA_V1).hash(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    CommitmentDeltaDigest(out)
}

impl BlockMMRLeaf {
    /// Hash the leaf tuple into a single 32-byte value (domain-separated).
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&self.orchard_root_digest.0);
        buf[32..64].copy_from_slice(&self.nullifier_block_digest.0);
        buf[64..].copy_from_slice(&self.commitment_delta_digest.0);
        let hash = Blake2bParams::new().hash_length(32).personal(DS_MMR_LEAF_V1).hash(&buf);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

/// Experimental block-level unified tachygram digest over on-chain primitives.
pub fn compute_unified_tachygram_block(nullifiers: &[[u8; 32]], commitments: &[[u8; 32]], value_commitments: &[[u8; 32]], fees: &[u64]) -> [u8; 32] {
    let mut buf = Vec::new();
    // preserve counts and order deterministically
    let mut tmp = Vec::with_capacity(4);
    // nullifiers
    tmp.clear(); encode_u32(nullifiers.len() as u32, &mut tmp); buf.extend_from_slice(&tmp);
    for nf in nullifiers { buf.extend_from_slice(nf); }
    // commitments
    tmp.clear(); encode_u32(commitments.len() as u32, &mut tmp); buf.extend_from_slice(&tmp);
    for cm in commitments { buf.extend_from_slice(cm); }
    // value commitments
    tmp.clear(); encode_u32(value_commitments.len() as u32, &mut tmp); buf.extend_from_slice(&tmp);
    for vc in value_commitments { buf.extend_from_slice(vc); }
    // fees
    tmp.clear(); encode_u32(fees.len() as u32, &mut tmp); buf.extend_from_slice(&tmp);
    for f in fees { buf.extend_from_slice(&f.to_be_bytes()); }
    let hash = Blake2bParams::new().hash_length(32).personal(DS_TG_UNIFIED_BLOCK_V1).hash(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

#[inline]
fn encode_u32(v: u32, out: &mut Vec<u8>) { out.extend_from_slice(&v.to_be_bytes()); }

