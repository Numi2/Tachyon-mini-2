//! Pasta cycle aliases and helpers.

use pasta_curves::{pallas, vesta};
use ff::{FromUniformBytes, PrimeField};

/// Scalar field of Vesta = base field of Pallas. Used for "outer" recursion steps.
pub type FrVesta = vesta::Scalar;

/// Scalar field of Pallas = base field of Vesta. Used for "inner" recursion steps.
pub type FrPallas = pallas::Scalar;

/// Wide-reduction helper for Pasta scalars.
pub trait FromBytesWide: PrimeField {
    fn from_bytes_wide_src(w: &[u8; 64]) -> Self;
}

impl FromBytesWide for FrVesta {
    #[inline]
    fn from_bytes_wide_src(w: &[u8; 64]) -> Self {
        <FrVesta as FromUniformBytes<64>>::from_uniform_bytes(w)
    }
}

impl FromBytesWide for FrPallas {
    #[inline]
    fn from_bytes_wide_src(w: &[u8; 64]) -> Self {
        <FrPallas as FromUniformBytes<64>>::from_uniform_bytes(w)
    }
}


