//! Aggregator for Tachyon: builds AggregateProofs from txids.

use anyhow::Result;
use crate::VerifyingKey;

pub const TXID_LEN: usize = 32;

/// Aggregate proof structure containing txids and proof bytes.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug)]
pub struct AggregateProof {
    // Exact txid list covered by this aggregate; order is preserved.
    pub txids: Vec<[u8; TXID_LEN]>,
    // Recursive proof bytes (Halo2 recursion). Exact format pinned later.
    pub proof: Vec<u8>,
}

#[derive(Default)]
pub struct Aggregator {
    txids: Vec<[u8; TXID_LEN]>,
}

impl Aggregator {
    pub fn new() -> Self { Self { txids: Vec::new() } }

    pub fn add_txid(&mut self, txid: [u8; TXID_LEN]) { self.txids.push(txid); }

    pub fn build(self, _vk: &VerifyingKey) -> Result<AggregateProof> {
        // Placeholder: construct aggregate with provided txids and empty proof bytes.
        Ok(AggregateProof { txids: self.txids, proof: Vec::new() })
    }
}

/// Convenience: single-shot aggregation
pub fn aggregate_txids(vk: &VerifyingKey, txids: Vec<[u8; TXID_LEN]>) -> Result<AggregateProof> {
    let mut agg = Aggregator::new();
    for id in txids { agg.add_txid(id); }
    agg.build(vk)
}

