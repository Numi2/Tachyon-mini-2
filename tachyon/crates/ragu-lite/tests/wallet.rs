use rand::{rngs::StdRng, RngCore, SeedableRng};
use ragu_lite::{
    wallet::{derive_nullifier}, Batch, Note, TachyObj, Wallet,
};
use ragu_lite::FrVesta;

fn rand32(rng: &mut StdRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

#[test]
fn wallet_end_to_end_recursive() {
    let mut rng = StdRng::seed_from_u64(42);
    let mut w = Wallet::new(&mut rng);

    // Create two incoming notes.
    let addr = w.address();
    let n1 = Note { commitment: Note::commit(&addr, 11, rand32(&mut rng)), value: 11, rseed: rand32(&mut rng) };
    let n2 = Note { commitment: Note::commit(&addr, 23, rand32(&mut rng)), value: 23, rseed: rand32(&mut rng) };

    // Stage batch 1: receive notes.
    let mut b1 = Batch::default();
    b1.commitments.push(n1.commitment);
    b1.commitments.push(n2.commitment);

    // Apply and prove first state.
    let p1 = w.apply_batch_and_prove(&b1);
    assert!(w.verify_latest());
    assert_eq!(p1.depth, 1);

    // Record ownership after acceptance.
    w.receive(n1.clone());
    w.receive(n2.clone());

    // Spend n1 in batch 2.
    let nf1 = w.spend(&n1.commitment);

    let mut b2 = Batch::default();
    b2.nullifiers.push(nf1);

    let p2 = w.apply_batch_and_prove(&b2);
    assert!(w.verify_latest());
    assert_eq!(p2.depth, 2);

    // Deterministic nullifier derivation.
    let nf1_again = derive_nullifier(&w.spend_key, &n1.commitment);
    assert_eq!(nf1.0, nf1_again.0);

    // Check state relation locally.
    let folded1 = b1.fold_accumulator(&Default::default());
    let folded2 = b2.fold_accumulator(&Default::default());

    // Recompute roots by contract.
    let meta1 = {
        let m = b1.derive_metadata_bytes();
        let h1 = blake3::hash(&m);
        let h2 = blake3::hash(h1.as_bytes());
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(h1.as_bytes());
        wide[32..].copy_from_slice(h2.as_bytes());
        FrVesta::from_bytes_wide(&wide)
    };
    let meta2 = {
        let m = b2.derive_metadata_bytes();
        let h1 = blake3::hash(&m);
        let h2 = blake3::hash(h1.as_bytes());
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(h1.as_bytes());
        wide[32..].copy_from_slice(h2.as_bytes());
        FrVesta::from_bytes_wide(&wide)
    };

    let root1 = meta1 * folded1; // old root = 0
    let root2 = root1 + meta2 * folded2;

    assert_eq!(p1.data.new_root, root1);
    assert_eq!(p2.data.old_root, root1);
    assert_eq!(p2.data.new_root, root2);
}


