use accum::{ipa, poly};
use pcd::{block_circuit::BlockPolyWitness, wallet_step::WalletStepWitness, api2};
use pasta_curves::{pallas, vesta::Scalar as FrVesta};
use ff::Field;

#[test]
fn block_poly_off_circuit_sanity() {
    // Small example with 3 roots.
    let roots = [3u64,5,7].map(FrVesta::from);
    let coeffs = poly::roots_to_coeffs(&roots);
    let p_i = {
        // Map coeffs (FrVesta) to Pallas scalars via a deterministic hash-to-scalar.
        let scalars: Vec<pallas::Scalar> = coeffs
            .iter()
            .map(|x| {
                let xb = ff::PrimeField::to_repr(x);
                let mut b32 = [0u8; 32];
                b32.copy_from_slice(xb.as_ref());
                ipa::map_vesta_scalar_to_pallas(&b32)
            })
            .collect();
        ipa::commit_coeffs(&scalars)
    };
    let a_i = ipa::g0();
    let wit = BlockPolyWitness { roots: roots.to_vec(), coeffs, p_i, a_i };
    let (_pub, _proof) = api2::prove_block(&api2::Params { k: 18 }, &wit).expect("off-circuit check");
}

#[test]
fn wallet_step_off_circuit_sanity() {
    // Use alpha != 0 and its inverse.
    let alpha = FrVesta::from(9u64);
    let alpha_inv = alpha.invert().unwrap();
    let p_i = ipa::g0();
    let a_i = ipa::g0();
    let s_i = ipa::g0();
    let wit = WalletStepWitness { v: FrVesta::from(1u64), alpha_i: alpha, alpha_inv, p_i, s_i, a_i };
    let (_pub, _proof) = api2::prove_wallet_step(&api2::Params { k: 18 }, &wit).expect("off-circuit step");
}


