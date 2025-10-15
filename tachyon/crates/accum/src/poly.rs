//! Minimal polynomial utilities over the Vesta scalar field.
//!
//! - Convert monic polynomial defined by its roots into coefficient vector.
//! - Evaluate polynomial at a point using Horner's method.

use pasta_curves::vesta::Scalar as FrVesta;
use rayon::prelude::*;
use ff::{Field, PrimeField};

/// Given roots a[0..k), return coefficients c[0..=k] of
/// p(X) = ∏_{j=0}^{k-1} (X - a_j) = c_0 + c_1 X + ... + c_k X^k.
/// Coefficients are in increasing degree order.
pub fn roots_to_coeffs(roots: &[FrVesta]) -> Vec<FrVesta> {
    let k = roots.len();
    // Start with polynomial 1
    let mut c = vec![FrVesta::ONE];
    for &r in roots {
        // Multiply current polynomial by (X - r)
        let mut next = vec![FrVesta::ZERO; c.len() + 1];
        for j in 0..c.len() {
            // Contribution to X^{j+1}
            next[j + 1] += c[j];
            // Contribution to X^{j}
            next[j] += (-r) * c[j];
        }
        c = next;
    }
    c
}

/// Evaluate polynomial with coefficients c[0..=k] at point x using Horner's method.
pub fn eval_horner(coeffs: &[FrVesta], x: FrVesta) -> FrVesta {
    let mut acc = FrVesta::ZERO;
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Evaluate ∏(x - a_j) directly from roots (useful for alpha_i computation).
pub fn eval_from_roots(roots: &[FrVesta], x: FrVesta) -> FrVesta {
    roots.iter().fold(FrVesta::ONE, |acc, a| acc * (x - *a))
}

/// Pad coefficient vector to a target length with zeros (no-op if already longer).
pub fn pad_coeffs_to(coeffs: &mut Vec<FrVesta>, target_len: usize) {
    if coeffs.len() < target_len {
        coeffs.resize(target_len, FrVesta::ZERO);
    }
}

fn convolve(a: &[FrVesta], b: &[FrVesta]) -> Vec<FrVesta> {
    let mut out = vec![FrVesta::ZERO; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] += ai * bj;
        }
    }
    out
}

fn roots_to_coeffs_divide_conquer(roots: &[FrVesta]) -> Vec<FrVesta> {
    if roots.is_empty() { return vec![FrVesta::ONE]; }
    if roots.len() == 1 { return vec![-roots[0], FrVesta::ONE]; }
    let mid = roots.len() / 2;
    let (left, right) = roots.split_at(mid);
    let (a, b) = rayon::join(|| roots_to_coeffs_divide_conquer(left), || roots_to_coeffs_divide_conquer(right));
    convolve(&a, &b)
}

/// Parallel coefficient generation using divide-and-conquer convolution.
pub fn roots_to_coeffs_parallel(roots: &[FrVesta]) -> Vec<FrVesta> {
    roots_to_coeffs_divide_conquer(roots)
}

/// Batch process multiple blocks' roots in parallel.
pub fn batch_roots_to_coeffs_parallel(batches: &[Vec<FrVesta>]) -> Vec<Vec<FrVesta>> {
    batches.par_iter().map(|r| roots_to_coeffs_parallel(r)).collect()
}

// ——— NTT/FFT helpers over FrVesta (size is power of two) ———

#[inline]
fn bitreverse(mut x: usize, lg_n: usize) -> usize {
    let mut y = 0usize;
    for _ in 0..lg_n { y = (y << 1) | (x & 1); x >>= 1; }
    y
}

fn fft_in_place(a: &mut [FrVesta], omega: FrVesta) {
    let n = a.len();
    let lg_n = n.trailing_zeros() as usize;
    // Bit-reverse permutation
    for i in 0..n {
        let j = bitreverse(i, lg_n);
        if i < j { a.swap(i, j); }
    }
    let mut len = 2;
    let mut w_m = omega;
    while len <= n {
        let half = len / 2;
        let mut w = FrVesta::ONE;
        for j in 0..half {
            let step = j * (n / len);
            if j == 0 { w = FrVesta::ONE; } else { w *= w_m; }
            let mut i = j;
            while i < n {
                let u = a[i];
                let v = a[i + half] * w;
                a[i] = u + v;
                a[i + half] = u - v;
                i += len;
            }
        }
        w_m = w_m * w_m; // square root progression
        len <<= 1;
    }
}

fn ifft_in_place(a: &mut [FrVesta], omega_inv: FrVesta) {
    let n = a.len();
    fft_in_place(a, omega_inv);
    let n_inv = FrVesta::from(n as u64).invert().unwrap();
    for v in a.iter_mut() { *v *= n_inv; }
}

#[inline]
fn omega_for_size(n: usize) -> (FrVesta, FrVesta) {
    // ROOT_OF_UNITY is 2^S primitive root; need omega = root^(2^{S - log2(n)})
    let s_total: u32 = pasta_curves::vesta::Scalar::S;
    let lg_n = n.trailing_zeros() as u32;
    let pow = 1u64 << (s_total - lg_n);
    let root = pasta_curves::vesta::Scalar::ROOT_OF_UNITY;
    let omega = root.pow_vartime(&[pow]);
    let omega_inv = omega.invert().unwrap();
    (omega, omega_inv)
}

fn convolution_fft(a: &[FrVesta], b: &[FrVesta]) -> Vec<FrVesta> {
    let needed = a.len() + b.len() - 1;
    let n = needed.next_power_of_two();
    let (omega, omega_inv) = omega_for_size(n);
    let mut fa = vec![FrVesta::ZERO; n];
    let mut fb = vec![FrVesta::ZERO; n];
    fa[..a.len()].copy_from_slice(a);
    fb[..b.len()].copy_from_slice(b);
    fft_in_place(&mut fa, omega);
    fft_in_place(&mut fb, omega);
    for i in 0..n { fa[i] *= fb[i]; }
    ifft_in_place(&mut fa, omega_inv);
    fa.truncate(needed);
    fa
}

/// FFT-accelerated coefficient generation using product tree + NTT convolution.
pub fn roots_to_coeffs_fft(roots: &[FrVesta]) -> Vec<FrVesta> {
    if roots.is_empty() { return vec![FrVesta::ONE]; }
    // Build leaves: (X - r)
    let mut polys: Vec<Vec<FrVesta>> = roots.iter().map(|&r| vec![-r, FrVesta::ONE]).collect();
    while polys.len() > 1 {
        let mut next = Vec::with_capacity((polys.len() + 1) / 2);
        for chunk in polys.chunks(2) {
            if chunk.len() == 2 {
                next.push(convolution_fft(&chunk[0], &chunk[1]));
            } else {
                next.push(chunk[0].clone());
            }
        }
        polys = next;
    }
    polys.pop().unwrap()
}

/// Batch FFT coefficient generation.
pub fn batch_roots_to_coeffs_fft(batches: &[Vec<FrVesta>]) -> Vec<Vec<FrVesta>> {
    batches.par_iter().map(|r| roots_to_coeffs_fft(r)).collect()
}


