# Accumulators in Tachyon

This document outlines the accumulator design for Tachyon, including sparse Merkle accumulators (SMA) and future vector-commitment backends.

## Overview

The `accum` crate provides a canonical API for accumulator roots, membership and non-membership proofs, and deterministic batch updates suitable for consensus.

## Sparse Merkle Accumulator (SMA)

The SMA is built over Poseidon hash for efficient circuit integration:

- **Tree height**: 32 (supports 2^32 leaves)
- **Node arity**: Binary (2 children per node)
- **Hash function**: Poseidon2 (Pasta field domain)

## Key Components

- **Root**: 32-byte accumulator root representing the current state
- **Membership Proof**: Path from leaf to root with sibling hashes
- **Non-membership Proof**: Shows that a leaf position is empty
- **Batch Update**: Deterministic, sorted batch operations for consensus

## Nullifier Window

The `NullifierSMAWindow` maintains a rolling window of recent accumulator roots to support efficient freshness checks for double-spend prevention.

## Vector Commitments (Pasta IPA backend)

Tachyon includes a vector-commitment backend over the Pasta cycle:

- Field/group orientation: Vesta (circuit field), Pallas G1 (commitment group).
- Per-block polynomial p_i(X)=∏(X−a_{ij}) with degree bound n=4096.
- Commitment P_i is a vector Pedersen over Pallas using chunked fixed bases (16×256).
- Consensus accumulator update uses domain-separated Poseidon hashes:
  - h_i = H_A(A_i, P_i), A_{i+1} = [h_i]A_i + P_i
  - h_i' = H_S(S_i, P_i'), S_{i+1} = [h_i']S_i + P_i'
- Blocks publish (P_i, h_i, A_{i+1}, proof), where the Halo2 proof (Vesta) SNARKs the identity at a random challenge r derived from (P_i, A_i), and checks P_i matches committed coefficients via an in-circuit MSM.

Wallets maintain (A_i, S_i) and for a secret tag v compute α_i = p_i(v). They update S using P_i' = P_i − [α_i]G_0 and prove α_i ≠ 0 via an inverse witness inside their step circuit. Final proof opens S_m at v to 0.

## Usage

- Off-circuit utilities: `accum::poly` (roots→coeffs/eval), `accum::ipa` (bases, commit, encoding), and `accum::poseidon` (domain-separated hashes).
- Circuits and stubs: `pcd::block_circuit` and `pcd::wallet_step` provide skeletons for Halo2 integration and off-circuit sanity checks.

