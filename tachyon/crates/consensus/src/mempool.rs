//! Mempool admission and block verification.

use anyhow::{anyhow, Result};
use accum::NullifierSMAWindow;
use primitives::TachyonBundle;

use crate::digest::*;

/// Admit a transaction into mempool: check nullifier freshness in the window.
/// Additional verification (PCD, signatures) is deferred to aggregate verification.
pub fn admit_tx(bundle: &TachyonBundle, window: &mut NullifierSMAWindow) -> Result<()> {
    for nf in &bundle.nullifiers {
        if !window.is_fresh(nf) {
            return Err(anyhow!("duplicate nullifier"));
        }
    }
    Ok(())
}

/// Verify block aggregates and update nullifier window with tx nullifiers.
/// This stub does not verify aggregate proofs yet.
pub fn verify_block(bundles: &[TachyonBundle], window: &mut NullifierSMAWindow) -> Result<()> {
    // Deterministic batch update placeholder; SMA backend will be wired later.
    let _ = window.window_len();
    // Compute per-block digests for PCD binding and MMR leaf construction.
    let mut all_nullifiers: Vec<[u8; 32]> = Vec::new();
    let mut all_commitments: Vec<[u8; 32]> = Vec::new();
    for bundle in bundles {
        all_nullifiers.extend_from_slice(&bundle.nullifiers);
        all_commitments.extend_from_slice(&bundle.commitments);
    }
    let _nf_digest = compute_nullifier_block_digest(&all_nullifiers);
    let _cm_delta_digest = compute_commitment_delta_digest(&all_commitments);
    // Orchard root digest will be provided by the commitment tree state machine
    // at block finalize; placeholder zeros here.
    let _orch_digest = compute_orchard_root_digest(&[0u8; 32]);
    let _leaf = BlockMMRLeaf {
        orchard_root_digest: _orch_digest,
        nullifier_block_digest: _nf_digest,
        commitment_delta_digest: _cm_delta_digest,
    };
    let _leaf_hash = _leaf.leaf_hash();
    Ok(())
}

