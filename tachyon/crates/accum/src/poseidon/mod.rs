//! Poseidon hash placeholders and tree helpers.
//! numan
//! This module will wrap halo2_gadgets Poseidon for circuits and provide
//! off-circuit hashing using Pasta fields. For now, we only expose stubs so
//! crates can compile and link.

/// Hash 64 bytes to a 32-byte field representation.
pub fn hash64_to32(_input: &[u8; 64]) -> [u8; 32] {
    // Placeholder: replace with Pasta Poseidon hash.
    [0u8; 32]
}

/// Combine two 32-byte nodes into a parent hash.
pub fn compress_nodes(_left: &[u8; 32], _right: &[u8; 32]) -> [u8; 32] {
    // Placeholder: replace with Poseidon permutation-based compression.
    [0u8; 32]
}
