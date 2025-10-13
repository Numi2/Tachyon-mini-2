## Tachyon v1 Accumulators (non-unified)

This document records the v1 decision to ship with two separate accumulators and defer any unification attempts until a later version.

- Commitment tree: Orchard-style incremental Merkle tree (depth 32), Poseidon2 compression. Anchors at block boundaries only. Range-anchors proven by transactions using a frontier attestation linking root_min → root_max.
- Nullifiers: Per-block ordered nullifier vector digested with BLAKE2b-256 and committed into the chain-history MMR leaf alongside the Orchard root and the commitment-delta digest.

Rationale:
- Keeps gadgets and range-anchor math simple; avoids tight interdependencies between note commitments and nullifier sets.
- Enables pruning validators: PCD cites per-block digests; validators verify against MMR without keeping old sets beyond the k-window for fast duplicate checks.

Consensus-facing summary:
- MMR leaf fields: `hashLatestOrchardRoot`, `hashNullifierDigest`, `hashCommitmentDeltaDigest`.
- Nullifier rule: On-chain nullifier is a deterministic function of note fields including a fixed, output-time nullifier flavor. Duplicate nullifiers are rejected. Per-spend flavoring is not permitted.

Experimental note: Unified Tachygram
- We expose an experimental unified tachygram digest at the tx and block levels that binds nullifiers, commitments, value commitments, and fees into a single 32-byte hash. This is not consensus-critical in v1 and is provided for analytics and future research only.

