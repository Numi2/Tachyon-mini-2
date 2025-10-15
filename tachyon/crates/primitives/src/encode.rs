//! Canonical encoding and decoding for Tachyon types.

use anyhow::{anyhow, Result};
use blake2b_simd::Params as Blake2bParams;

use crate::types::*;

// ——— Canonical encoding version ———

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

pub fn encode_u8(v: u8, out: &mut Vec<u8>) { out.push(v); }
pub fn encode_u32(v: u32, out: &mut Vec<u8>) { out.extend_from_slice(&v.to_be_bytes()); }
pub fn encode_u64(v: u64, out: &mut Vec<u8>) { out.extend_from_slice(&v.to_be_bytes()); }

pub fn read_u8(data: &mut &[u8]) -> Result<u8> {
    if data.len() < 1 { return Err(anyhow!("unexpected EOF")); }
    let v = data[0];
    *data = &data[1..];
    Ok(v)
}

pub fn read_u32(data: &mut &[u8]) -> Result<u32> {
    if data.len() < 4 { return Err(anyhow!("unexpected EOF")); }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[..4]);
    *data = &data[4..];
    Ok(u32::from_be_bytes(buf))
}

pub fn read_u64(data: &mut &[u8]) -> Result<u64> {
    if data.len() < 8 { return Err(anyhow!("unexpected EOF")); }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    *data = &data[8..];
    Ok(u64::from_be_bytes(buf))
}

pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_u32(bytes.len() as u32, out);
    out.extend_from_slice(bytes);
}

pub fn read_vec(data: &mut &[u8]) -> Result<Vec<u8>> {
    let len = read_u32(data)? as usize;
    if data.len() < len { return Err(anyhow!("unexpected EOF")); }
    let v = data[..len].to_vec();
    *data = &data[len..];
    Ok(v)
}

pub fn read_fixed<const N: usize>(data: &mut &[u8]) -> Result<[u8; N]> {
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

