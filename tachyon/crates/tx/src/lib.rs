//! Tachyon transaction types: tachyactions, tachygrams, tachystamps.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct Tachygram(pub [u8; 32]);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Tachyaction {
    Spend { nf: [u8; 32], value: u64 },
    Output { cm: [u8; 32], value: u64 },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct TachystampBytes(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct AnchorRange { pub start: [u8; 32], pub end: [u8; 32] }

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TachyonBundle {
    pub actions: Vec<Tachyaction>,
    pub grams: Vec<Tachygram>,
    pub stamp: Option<TachystampBytes>,
    pub range: Option<AnchorRange>,
    // Explicit on-chain primitives for validation and aggregation.
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub value_commitment: [u8; 32],
    pub fee: u64,
}

impl TachyonBundle {
    pub fn new() -> Self {
        Self {
            actions: vec![],
            grams: vec![],
            stamp: None,
            range: None,
            nullifiers: vec![],
            commitments: vec![],
            value_commitment: [0u8; 32],
            fee: 0,
        }
    }
}

// ————————————————————————————————————————————————————————————————————————————
// Tachyon consensus types (new pool): RangeAnchor, Tachystamp, AggregateProof
// Canonical encodings kept minimal and versioned for ZIP‑244 integration.

use anyhow::{anyhow, Result};
use blake2b_simd::Params as Blake2bParams;

pub const TACHYGRAM_LEN: usize = 32;
pub const ROOT_LEN: usize = 32;
pub const REDPALLAS_SIG_LEN: usize = 64;
pub const TXID_LEN: usize = 32;

// ————————————————————————————————————————————————————————————————————————————
// Nullifier flavoring (fixed at output creation) and deterministic derivations
// ————————————————————————————————————————————————————————————————————————————

/// Fixed, output-time nullifier flavor committed in the note.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct NullifierFlavor(pub [u8; 32]);

/// Deterministic on-chain nullifier derived from fixed flavor and note fields.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct OnChainNullifier(pub [u8; 32]);

/// Wallet-private off-chain sync tag for OSS indices (never on-chain).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct OffchainSyncTag(pub [u8; 32]);

/// Domain separators for BLAKE2b-256 derivations.
const DS_FLAVOR_V1: &[u8; 16] = b"tachyon.flavor\0\0"; // 14 + 2 = 16
const DS_NF_V1: &[u8; 16] = b"tachyon.nf.v1\0\0\0"; // 13 + 3 = 16
const DS_SYNC_V1: &[u8; 16] = b"tachyon.sync.v1\0"; // 15 + 1 = 16
const DS_TG_UNIFIED_TX_V1: &[u8; 16] = b"tg.unified.tx.v1"; // exactly 16

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

// ————————————————————————————————————————————————————————————————————————————
// Unified Tachygram (experimental, non-consensus): tx-level digest
// ————————————————————————————————————————————————————————————————————————————

/// Experimental digest binding on-chain tx primitives into one 32-byte value.
/// Not consensus-critical in v1; provided for analytics and future research.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct UnifiedTachygramDigest(pub [u8; 32]);

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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct RedPallasSig(pub [u8; REDPALLAS_SIG_LEN]);

impl serde::Serialize for RedPallasSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for RedPallasSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = RedPallasSig;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "a 64-byte redpallas signature")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != REDPALLAS_SIG_LEN {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut out = [0u8; REDPALLAS_SIG_LEN];
                out.copy_from_slice(v);
                Ok(RedPallasSig(out))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = [0u8; REDPALLAS_SIG_LEN];
                for i in 0..REDPALLAS_SIG_LEN {
                    out[i] = match seq.next_element::<u8>()? {
                        Some(b) => b,
                        None => return Err(serde::de::Error::invalid_length(i, &self)),
                    };
                }
                Ok(RedPallasSig(out))
            }
        }
        deserializer.deserialize_bytes(SigVisitor)
    }
}

impl core::fmt::Debug for RedPallasSig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RedPallasSig(..)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RangeAnchor {
    pub min_pos: u64,
    pub max_pos: u64,
    pub root_min: [u8; ROOT_LEN],
    pub root_max: [u8; ROOT_LEN],
    // Compact attestation binding intermediate roots between [min_pos, max_pos].
    pub frontier_attestation: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct PcdProof(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Tachystamp {
    pub range_anchor: RangeAnchor,
    pub tachygrams: Vec<Tachygram>,
    pub auth: RedPallasSig,
    pub pcd_proof: PcdProof,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct AggregateProof {
    // Exact txid list covered by this aggregate; order is preserved.
    pub txids: Vec<[u8; TXID_LEN]>,
    // Recursive proof bytes (Halo2 recursion). Exact format pinned later.
    pub proof: Vec<u8>,
}

// ——— Canonical encoding helpers (stable v1 placeholder) ———

const ENC_V1: u8 = 1; // version tag for canonical encodings

impl Tachystamp {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 + 2 + 2);
        out.push(ENC_V1);
        encode_range_anchor(&self.range_anchor, &mut out);
        encode_vec_tachygram(&self.tachygrams, &mut out);
        out.extend_from_slice(&self.auth.0);
        encode_bytes(&self.pcd_proof.0, &mut out);
        out
    }

    pub fn from_canonical_bytes(mut data: &[u8]) -> Result<Self> {
        let ver = read_u8(&mut data)?;
        if ver != ENC_V1 { return Err(anyhow!("unsupported encoding version: {}", ver)); }
        let range_anchor = decode_range_anchor(&mut data)?;
        let tachygrams = decode_vec_tachygram(&mut data)?;
        let auth = {
            let bytes = read_fixed::<REDPALLAS_SIG_LEN>(&mut data)?;
            RedPallasSig(bytes)
        };
        let pcd_proof = PcdProof(read_vec(&mut data)?);
        if !data.is_empty() { return Err(anyhow!("trailing bytes in Tachystamp")); }
        Ok(Tachystamp { range_anchor, tachygrams, auth, pcd_proof })
    }

    // Placeholder authorizing-data contribution for ZIP‑244 integration.
    pub fn zip244_authorizing_data_bytes(&self) -> Vec<u8> {
        self.to_canonical_bytes()
    }

    pub fn authorizing_digest32(&self) -> [u8; 32] {
        let bytes = self.zip244_authorizing_data_bytes();
        let hash = Blake2bParams::new().hash_length(32).hash(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

impl AggregateProof {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + self.txids.len() * TXID_LEN);
        out.push(ENC_V1);
        encode_vec_txid(&self.txids, &mut out);
        encode_bytes(&self.proof, &mut out);
        out
    }

    pub fn from_canonical_bytes(mut data: &[u8]) -> Result<Self> {
        let ver = read_u8(&mut data)?;
        if ver != ENC_V1 { return Err(anyhow!("unsupported encoding version: {}", ver)); }
        let txids = decode_vec_txid(&mut data)?;
        let proof = read_vec(&mut data)?;
        if !data.is_empty() { return Err(anyhow!("trailing bytes in AggregateProof")); }
        Ok(AggregateProof { txids, proof })
    }
}

// ——— Encoding primitives ———

fn encode_u8(v: u8, out: &mut Vec<u8>) { out.push(v); }
fn encode_u32(v: u32, out: &mut Vec<u8>) { out.extend_from_slice(&v.to_be_bytes()); }
fn encode_u64(v: u64, out: &mut Vec<u8>) { out.extend_from_slice(&v.to_be_bytes()); }

fn read_u8(data: &mut &[u8]) -> Result<u8> {
    if data.len() < 1 { return Err(anyhow!("unexpected EOF")); }
    let v = data[0];
    *data = &data[1..];
    Ok(v)
}

fn read_u32(data: &mut &[u8]) -> Result<u32> {
    if data.len() < 4 { return Err(anyhow!("unexpected EOF")); }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[..4]);
    *data = &data[4..];
    Ok(u32::from_be_bytes(buf))
}

fn read_u64(data: &mut &[u8]) -> Result<u64> {
    if data.len() < 8 { return Err(anyhow!("unexpected EOF")); }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    *data = &data[8..];
    Ok(u64::from_be_bytes(buf))
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_u32(bytes.len() as u32, out);
    out.extend_from_slice(bytes);
}

fn read_vec(data: &mut &[u8]) -> Result<Vec<u8>> {
    let len = read_u32(data)? as usize;
    if data.len() < len { return Err(anyhow!("unexpected EOF")); }
    let v = data[..len].to_vec();
    *data = &data[len..];
    Ok(v)
}

fn read_fixed<const N: usize>(data: &mut &[u8]) -> Result<[u8; N]> {
    if data.len() < N { return Err(anyhow!("unexpected EOF")); }
    let mut out = [0u8; N];
    out.copy_from_slice(&data[..N]);
    *data = &data[N..];
    Ok(out)
}

fn encode_range_anchor(a: &RangeAnchor, out: &mut Vec<u8>) {
    encode_u8(ENC_V1, out);
    encode_u64(a.min_pos, out);
    encode_u64(a.max_pos, out);
    out.extend_from_slice(&a.root_min);
    out.extend_from_slice(&a.root_max);
    encode_bytes(&a.frontier_attestation, out);
}

fn decode_range_anchor(data: &mut &[u8]) -> Result<RangeAnchor> {
    let _ver = read_u8(data)?;
    let min_pos = read_u64(data)?;
    let max_pos = read_u64(data)?;
    let root_min = read_fixed::<ROOT_LEN>(data)?;
    let root_max = read_fixed::<ROOT_LEN>(data)?;
    let frontier_attestation = read_vec(data)?;
    Ok(RangeAnchor { min_pos, max_pos, root_min, root_max, frontier_attestation })
}

fn encode_vec_tachygram(v: &[Tachygram], out: &mut Vec<u8>) {
    encode_u32(v.len() as u32, out);
    for t in v { out.extend_from_slice(&t.0); }
}

fn decode_vec_tachygram(data: &mut &[u8]) -> Result<Vec<Tachygram>> {
    let len = read_u32(data)? as usize;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(Tachygram(read_fixed::<TACHYGRAM_LEN>(data)?));
    }
    Ok(v)
}

fn encode_vec_txid(v: &[[u8; TXID_LEN]], out: &mut Vec<u8>) {
    encode_u32(v.len() as u32, out);
    for id in v { out.extend_from_slice(id); }
}

fn decode_vec_txid(data: &mut &[u8]) -> Result<Vec<[u8; TXID_LEN]>> {
    let len = read_u32(data)? as usize;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len { v.push(read_fixed::<TXID_LEN>(data)?); }
    Ok(v)
}

