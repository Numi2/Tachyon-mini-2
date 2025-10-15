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

## Future: Vector Commitments

The `VectorCommitment` trait is provided as a future-ready interface for swapping to IPA-based vector commitments (Verkle-style) while maintaining API compatibility.

## Usage

See `crates/accum/src/lib.rs` for the full API documentation.

