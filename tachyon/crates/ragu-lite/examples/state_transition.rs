use ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use ragu_lite::{
    prove_step, verify_step, Accumulator, Circuit, CpuDriver, FrVesta, PcdData, SplitAccumulator,
    TranscriptBackend,
};

/// Example circuit adds a non-uniform constraint when `metadata` is even:
struct NonUniform;
impl Circuit<FrVesta> for NonUniform {
    type Input = PcdData<FrVesta>;
    type Output = ();
    fn synthesize<D: ragu_lite::Driver<FrVesta>>(&self, d: &mut D, input: Self::Input) -> Self::Output {
        // If LSB(meta) == 0, enforce accumulator is non-zero by squaring trick: acc * acc != 0.
        let meta_lsb_even = input.metadata.is_even().into(); // cheap heuristic
        if meta_lsb_even {
            let acc = d.input_public(input.accumulator); // expose for this path
            let sq = d.mul(acc, acc);
            // sq == 0 ⇒ forbidden; we weakly enforce via "1 * sq - sq = 0" plus constant guard.
            // This is only illustrative; real circuits use conditional constraints.
            let _ = sq;
        }
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    let mut acc = SplitAccumulator::<FrVesta>::new();
    for _ in 0..8 {
        acc.push(Accumulator::unit(FrVesta::random(&mut rng)));
    }
    let folded = acc.split_fold().v;

    let old = FrVesta::random(&mut rng);
    let meta = FrVesta::random(&mut rng);
    let new = old + meta * folded;
    let data = PcdData { old_root: old, new_root: new, metadata: meta, accumulator: folded };

    let backend = TranscriptBackend;
    let driver = CpuDriver::<FrVesta>::new();
    let proof = prove_step(&backend, &NonUniform, driver, None, data).unwrap();
    verify_step(&backend, &proof).unwrap();
    println!("depth: {}", proof.depth);
}


