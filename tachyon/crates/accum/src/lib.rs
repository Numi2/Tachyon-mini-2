//! Sparse Merkle Accumulator (SMA) over Poseidon for Tachyon.\n//!\n//! This crate provides a canonical API for accumulator roots, membership and\n//! non-membership proofs, and deterministic batch updates suitable for\n//! consensus.\n\npub mod poseidon;\n\nuse serde::{Deserialize, Serialize};\n\n/// Accumulator parameters (opinionated defaults for Tachyon v1).\npub mod params {\n    /// Tree height (depth) = 32 → 2^32 leaves.\n    pub const ACCUM_HEIGHT: usize = 32;\n    /// Node arity (binary) for Poseidon2 compression; revisit after benchmarks.\n    pub const NODE_ARITY: usize = 2;\n}\n\n/// 32-byte accumulator root (Poseidon-based tree root, Pasta field domain).\n#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]\npub struct Root(pub [u8; 32]);\n\n/// Sparse Merkle path element.\n#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]\npub struct PathElem {\n    pub sibling: [u8; 32],\n    pub is_right: bool,\n}\n\n/// Sparse Merkle path (from leaf to root), most significant bit first.\n#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]\npub struct Path(pub Vec<PathElem>);\n\n/// Membership proof binds a key to presence at an empty/non-empty leaf.\n#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]\npub struct MembershipProof {\n    pub key_hash: [u8; 32],\n    pub path: Path,\n}\n\n/// Non-membership proof shows that the leaf for key is empty.\n#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]\npub struct NonMembershipProof {\n    pub key_hash: [u8; 32],\n    pub path: Path,\n}\n\n/// Canonical batch update items: key = H(item), value is presence bit {0,1}.\n#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]\npub struct BatchItem {\n    pub key_hash: [u8; 32],\n    pub present: bool,\n}\n\n/// Deterministic batch update operation (sorted by key, no duplicates).\n#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]\npub struct BatchUpdate(pub Vec<BatchItem>);\n\n/// SMA interface for consensus and circuits.\npub trait SparseMerkleAccumulator {\n    /// Domain size exponent (tree height k so 2^k leaves).\n    fn height(&self) -> usize;\n\n    /// Current root.\n    fn root(&self) -> Root;\n\n    /// Prove membership of key.\n    fn prove_membership(&self, key_hash: [u8; 32]) -> MembershipProof;\n\n    /// Prove non-membership of key.\n    fn prove_non_membership(&self, key_hash: [u8; 32]) -> NonMembershipProof;\n\n    /// Apply a canonical batch and return the new root.\n    fn apply_batch(&mut self, batch: &BatchUpdate) -> Root;\n}\n\n/// Verkle-ready interface (no pairings): allows swapping a vector-commitment\n/// backend later (e.g., IPA on Pasta) while keeping Merkle today.\npub trait VectorCommitment {\n    /// Domain size exponent (matches `SparseMerkleAccumulator::height`).\n    fn height(&self) -> usize;\n    /// Commitment root bytes.\n    fn commit(&self) -> Root;\n    /// Membership witness for a position (or key hash mapping to position).\n    fn open(&self, position: u64) -> Vec<u8>;\n    /// Verify an opening against the commitment.\n    fn verify(commitment: &Root, position: u64, witness: &[u8]) -> bool;\n}\n\n/// Canonical serialization helpers for on-chain objects.\npub mod ser {\n    use super::*;\n\n    pub fn serialize_root(root: &Root) -> [u8; 32] { root.0 }\n\n    pub fn serialize_batch(batch: &BatchUpdate) -> Vec<u8> {\n        // Deterministic little-endian encoding: [n][items...]\n        let mut out = Vec::with_capacity(8 + batch.0.len() * (32 + 1));\n        out.extend_from_slice(&(batch.0.len() as u64).to_le_bytes());\n        for it in &batch.0 {\n            out.extend_from_slice(&it.key_hash);\n            out.push(if it.present { 1 } else { 0 });\n        }\n        out\n    }\n}\n\n/// Rolling window of nullifiers backed by an SMA root history.\n#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn batch_encoding_roundtrip_size() {\n        let batch = BatchUpdate(vec![\n            BatchItem { key_hash: [1u8; 32], present: true },\n            BatchItem { key_hash: [2u8; 32], present: false },\n        ]);\n        let enc = ser::serialize_batch(&batch);\n        assert_eq!(enc.len(), 8 + 2 * (32 + 1));\n    }\n}\n