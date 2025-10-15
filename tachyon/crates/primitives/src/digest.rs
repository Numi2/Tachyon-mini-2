//! Digest derivation functions for nullifiers, sync tags, and tachygrams.

use blake2b_simd::Params as Blake2bParams;
use pasta_curves::vesta::Scalar as FrVesta;
use ff::FromUniformBytes;

use crate::types::*;
use crate::encode::{encode_u32, encode_u64};

/// Domain separators for BLAKE2b-256 derivations.
const DS_FLAVOR_V1: &[u8; 16] = b"tachyon.flavor\0\0"; // 14 + 2 = 16
const DS_NF_V1: &[u8; 16] = b"tachyon.nf.v1\0\0\0"; // 13 + 3 = 16
const DS_SYNC_V1: &[u8; 16] = b"tachyon.sync.v1\0"; // 15 + 1 = 16
const DS_TG_UNIFIED_TX_V1: &[u8; 16] = b"tg.unified.tx.v1"; // exactly 16
const DS_TACHYGRAM_TO_FR_V1: &[u8; 16] = b"tg.to_fr.v1\0\0\0\0\0"; // exactly 16 bytes

/// Derive the fixed nullifier flavor at output creation. This value must be
/// committed inside the note and is immutable for the note's lifetime.
///
/// Inputs:
/// - note_commitment: canonical 32-byte note commitment `cm`
/// - note_randomness: output-time secret randomness unique to the note
pub fn derive_fixed_flavor(note_commitment: &[u8; 32], note_randomness: &[u8; 32]) -> NullifierFlavor {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(note_commitment);
    input[32..].copy_from_slice(note_randomness);
    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(DS_FLAVOR_V1)
        .hash(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    NullifierFlavor(out)
}

/// Derive the deterministic on-chain nullifier from the fixed flavor and
/// public note commitment. This must be used for `Tachyaction::Spend` `nf` and
/// is globally unique per note. Per-spend flavoring is NOT permitted.
pub fn derive_onchain_nullifier(fixed_flavor: &NullifierFlavor, note_commitment: &[u8; 32]) -> OnChainNullifier {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&fixed_flavor.0);
    input[32..].copy_from_slice(note_commitment);
    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(DS_NF_V1)
        .hash(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    OnChainNullifier(out)
}

/// Derive a wallet-private off-chain sync tag using a view key (or domain
/// secret) and the fixed flavor. Never appears on-chain.
pub fn derive_offchain_sync_tag(view_key: &[u8; 32], fixed_flavor: &NullifierFlavor) -> OffchainSyncTag {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(view_key);
    input[32..].copy_from_slice(&fixed_flavor.0);
    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(DS_SYNC_V1)
        .hash(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    OffchainSyncTag(out)
}

/// Derive a unified tachygram digest from a bundle's on-chain primitives.
/// Canonical encoding preserves order and includes counts.
pub fn derive_unified_tachygram_tx(bundle: &TachyonBundle) -> UnifiedTachygramDigest {
    let mut buf = Vec::with_capacity(8 + bundle.nullifiers.len() * 32 + bundle.commitments.len() * 32 + 32 + 8);
    // nullifiers
    encode_u32(bundle.nullifiers.len() as u32, &mut buf);
    for nf in &bundle.nullifiers { buf.extend_from_slice(nf); }
    // commitments
    encode_u32(bundle.commitments.len() as u32, &mut buf);
    for cm in &bundle.commitments { buf.extend_from_slice(cm); }
    // value commitment and fee
    buf.extend_from_slice(&bundle.value_commitment);
    encode_u64(bundle.fee, &mut buf);
    let hash = Blake2bParams::new().hash_length(32).personal(DS_TG_UNIFIED_TX_V1).hash(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    UnifiedTachygramDigest(out)
}

/// Canonical hash-to-field for 32-byte tachygrams → Fr(Vesta).
/// Uses BLAKE2b-512 with domain separation and wide reduction.
pub fn tachygram_to_fr(tag: &[u8; 32]) -> FrVesta {
    let hash = Blake2bParams::new().hash_length(64).personal(DS_TACHYGRAM_TO_FR_V1).hash(tag);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(hash.as_bytes());
    <FrVesta as FromUniformBytes<64>>::from_uniform_bytes(&wide)
}

