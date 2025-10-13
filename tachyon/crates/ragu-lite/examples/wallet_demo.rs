use rand::{rngs::StdRng, SeedableRng};
use ragu_lite::{Batch, Note, Wallet};

fn main() {
    let mut rng = StdRng::seed_from_u64(1717);
    let mut w = Wallet::new(&mut rng);

    // Receive a note.
    let addr = w.address();
    let n = Note { commitment: Note::commit(&addr, 5, [7u8; 32]), value: 5, rseed: [7u8; 32] };
    let mut b1 = Batch::default();
    b1.commitments.push(n.commitment);
    let _p1 = w.apply_batch_and_prove(&b1);

    // Spend it.
    w.receive(n.clone());
    let nf = w.spend(&n.commitment);
    let mut b2 = Batch::default();
    b2.nullifiers.push(nf);
    let p2 = w.apply_batch_and_prove(&b2);

    println!("wallet root: 0x{}", hex::encode(p2.data.new_root.to_repr().as_ref()));
    println!("proof depth: {}", p2.depth);
}


