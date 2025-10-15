//! Poseidon2 hash wrappers and tree helpers for the Pasta field domain.
//!
//! Off-circuit helpers expose domain-separated hashing for consensus objects
//! and interim accumulator states. Circuit adapters can be added later using
//! halo2_gadgets Poseidon chips.

use blake2b_simd::Params as Blake2bParams;
use pasta_curves::vesta::Scalar as FrVesta;
use ff::FromUniformBytes;

const DOM_A_H: &[u8] = b"tachyon:A/h";       // 12
const DOM_S_H: &[u8] = b"tachyon:S/h";       // 12
const DOM_BLOCK_R: &[u8] = b"tachyon:block:r"; // 16

/// Hash 64 bytes to a Pasta field element (Vesta scalar) and return its 32-byte LE repr.
pub fn hash64_to32(input: &[u8; 64]) -> [u8; 32] {
    let mut wide = [0u8; 64];
    // Use Blake2b-512 as a domain-separated PRF to derive uniform bytes.
    let hash = Blake2bParams::new().hash_length(64).hash(input);
    wide.copy_from_slice(hash.as_bytes());
    let f = <FrVesta as FromUniformBytes<64>>::from_uniform_bytes(&wide);
    let mut out = [0u8; 32];
    out.copy_from_slice(&ff::PrimeField::to_repr(&f));
    out
}

/// Combine two 32-byte nodes into a parent hash (Poseidon-domain placeholder).
/// For now, derive a Vesta field via Blake2b-512(left||right) and return LE bytes.
pub fn compress_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    hash64_to32(&input)
}

/// Domain-separated hash for accumulator update: h_i = H_A(A_i, P_i).
pub fn hash_A_h(a_i: &[u8; 32], p_i: &[u8; 32]) -> [u8; 32] {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(a_i);
    m[32..].copy_from_slice(p_i);
    let tag = Blake2bParams::new().hash_length(32).personal(DOM_A_H).hash(&m);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_bytes());
    out
}

/// Domain-separated hash for secondary accumulator update: h_i' = H_S(S_i, P_i').
pub fn hash_S_h(s_i: &[u8; 32], p_i_prime: &[u8; 32]) -> [u8; 32] {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(s_i);
    m[32..].copy_from_slice(p_i_prime);
    let tag = Blake2bParams::new().hash_length(32).personal(DOM_S_H).hash(&m);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_bytes());
    out
}

/// Derive evaluation challenge r from block commitment and accumulator state.
pub fn derive_block_r(p_i: &[u8; 32], a_i: &[u8; 32]) -> [u8; 32] {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(p_i);
    m[32..].copy_from_slice(a_i);
    let tag = Blake2bParams::new().hash_length(32).personal(DOM_BLOCK_R).hash(&m);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_bytes());
    out
}
