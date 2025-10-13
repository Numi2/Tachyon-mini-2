//! Sparse Merkle Accumulator (SMA) over Poseidon for Tachyon.
//!
//! This crate provides a canonical API for accumulator roots, membership and
//! non-membership proofs, and deterministic batch updates suitable for
//! consensus.

pub mod poseidon;

use serde::{Deserialize, Serialize};

/// Accumulator parameters (opinionated defaults for Tachyon v1).
pub mod params {
    /// Tree height (depth) = 32 → 2^32 leaves.
    pub const ACCUM_HEIGHT: usize = 32;
    /// Node arity (binary) for Poseidon2 compression; revisit after benchmarks.
    pub const NODE_ARITY: usize = 2;
}

/// 32-byte accumulator root (Poseidon-based tree root, Pasta field domain).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub struct Root(pub [u8; 32]);

/// Sparse Merkle path element.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PathElem {
    pub sibling: [u8; 32],
    pub is_right: bool,
}

/// Sparse Merkle path (from leaf to root), most significant bit first.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct Path(pub Vec<PathElem>);

/// Membership proof binds a key to presence at an empty/non-empty leaf.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct MembershipProof {
    pub key_hash: [u8; 32],
    pub path: Path,
}

/// Non-membership proof shows that the leaf for key is empty.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct NonMembershipProof {
    pub key_hash: [u8; 32],
    pub path: Path,
}

/// Canonical batch update items: key = H(item), value is presence bit {0,1}.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct BatchItem {
    pub key_hash: [u8; 32],
    pub present: bool,
}

/// Deterministic batch update operation (sorted by key, no duplicates).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct BatchUpdate(pub Vec<BatchItem>);

/// SMA interface for consensus and circuits.
pub trait SparseMerkleAccumulator {
    /// Domain size exponent (tree height k so 2^k leaves).
    fn height(&self) -> usize;

    /// Current root.
    fn root(&self) -> Root;

    /// Prove membership of key.
    fn prove_membership(&self, key_hash: [u8; 32]) -> MembershipProof;

    /// Prove non-membership of key.
    fn prove_non_membership(&self, key_hash: [u8; 32]) -> NonMembershipProof;

    /// Apply a canonical batch and return the new root.
    fn apply_batch(&mut self, batch: &BatchUpdate) -> Root;
}

/// Verkle-ready interface (no pairings): allows swapping a vector-commitment
/// backend later (e.g., IPA on Pasta) while keeping Merkle today.
pub trait VectorCommitment {
    /// Domain size exponent (matches `SparseMerkleAccumulator::height`).
    fn height(&self) -> usize;
    /// Commitment root bytes.
    fn commit(&self) -> Root;
    /// Membership witness for a position (or key hash mapping to position).
    fn open(&self, position: u64) -> Vec<u8>;
    /// Verify an opening against the commitment.
    fn verify(commitment: &Root, position: u64, witness: &[u8]) -> bool;
}

/// Canonical serialization helpers for on-chain objects.
pub mod ser {
    use super::*;

    pub fn serialize_root(root: &Root) -> [u8; 32] { root.0 }

    pub fn serialize_batch(batch: &BatchUpdate) -> Vec<u8> {
        // Deterministic little-endian encoding: [n][items...]
        let mut out = Vec::with_capacity(8 + batch.0.len() * (32 + 1));
        out.extend_from_slice(&(batch.0.len() as u64).to_le_bytes());
        for it in &batch.0 {
            out.extend_from_slice(&it.key_hash);
            out.push(if it.present { 1 } else { 0 });
        }
        out
    }
}

/// Rolling window of nullifiers backed by an SMA root history.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NullifierSMAWindow {
    /// Current accumulator root for the window.
    pub current_root: Root,
    /// Optional prior roots for windowed validation (most-recent-first).
    pub recent_roots: Vec<Root>,
    /// Height of the underlying accumulator.
    pub height: usize,
}

impl NullifierSMAWindow {
    /// Create a new window with the given height and initial root.
    pub fn new(height: usize, initial_root: Root) -> Self {
        Self { current_root: initial_root, recent_roots: Vec::new(), height }
    }

    /// Advance the window by applying a deterministic batch of nullifier insertions.
    /// Returns the new root.
    pub fn apply_batch(&mut self, batch: &BatchUpdate) -> Root {
        // Placeholder: in a full implementation this would delegate to an SMA backend.
        // Here we simply record the previous root and return the unchanged root.
        let _ = batch;
        self.recent_roots.insert(0, self.current_root);
        self.current_root
    }

    /// Whether a key hash is fresh within the current window (non-membership check).
    pub fn is_fresh(&self, _key_hash: &[u8; 32]) -> bool {
        // Placeholder until SMA backend is wired; treat unknown as fresh.
        true
    }

    /// Returns the maximum number of historical roots retained.
    pub fn window_len(&self) -> usize { self.recent_roots.len() + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_encoding_roundtrip_size() {
        let batch = BatchUpdate(vec![
            BatchItem { key_hash: [1u8; 32], present: true },
            BatchItem { key_hash: [2u8; 32], present: false },
        ]);
        let enc = ser::serialize_batch(&batch);
        assert_eq!(enc.len(), 8 + 2 * (32 + 1));
    }
}