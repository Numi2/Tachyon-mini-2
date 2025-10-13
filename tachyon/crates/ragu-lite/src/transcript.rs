//! Fiat–Shamir transcript over BLAKE3.

use blake3::Hasher;
use ff::{FromUniformBytes, PrimeField};

#[derive(Default, Clone)]
pub struct FsTranscript {
    state: Vec<u8>,
}

impl FsTranscript {
    pub fn new(label: &[u8]) -> Self {
        let mut t = Self { state: Vec::new() };
        t.absorb(label);
        t
    }

    pub fn absorb_bytes(&mut self, bytes: &[u8]) {
        self.state.extend_from_slice(bytes);
    }

    pub fn absorb_field<F: PrimeField>(&mut self, f: &F) {
        self.state.extend_from_slice(PrimeField::to_repr(f).as_ref());
    }

    pub fn absorb(&mut self, bytes: &[u8]) { self.absorb_bytes(bytes); }

    pub fn challenge_bytes(&self, label: &[u8]) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(&self.state);
        h.update(label);
        *h.finalize().as_bytes()
    }

    pub fn challenge_scalar<F: PrimeField + FromUniformBytes<64>>(&self, label: &[u8]) -> F {
        // Wide-reduce 64 bytes to a field element.
        let mut h = Hasher::new();
        h.update(&self.state);
        h.update(label);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(h.finalize().as_bytes());
        // Slight domain separation.
        out[32..].copy_from_slice(Hasher::new().finalize().as_bytes());
        <F as FromUniformBytes<64>>::from_uniform_bytes(&out)
    }
}


