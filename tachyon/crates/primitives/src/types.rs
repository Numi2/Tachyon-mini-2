//! Core transaction types for Tachyon.

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

impl Default for TachyonBundle {
    fn default() -> Self {
        Self::new()
    }
}

// ————————————————————————————————————————————————————————————————————————————
// Tachyon consensus types (new pool): RangeAnchor, Tachystamp, AggregateProof
// Canonical encodings kept minimal and versioned for ZIP‑244 integration.

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

/// Experimental digest binding on-chain tx primitives into one 32-byte value.
/// Not consensus-critical in v1; provided for analytics and future research.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct UnifiedTachygramDigest(pub [u8; 32]);

