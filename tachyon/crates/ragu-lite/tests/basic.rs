use ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use ragu_lite::{
    prove_step, verify_step, Accumulator, Circuit, CpuDriver, FrPallas, FrVesta, Instance,
    Pcd, PcdData, SplitAccumulator, TranscriptBackend,
};

struct Noop;
impl<F: ff::PrimeField> Circuit<F> for Noop {
    type Input = PcdData<F>;
    type Output = ();
    fn synthesize<D: ragu_lite::Driver<F>>(&self, _d: &mut D, _input: Self::Input) -> Self::Output {}
}

#[test]
fn split_accum_and_step_vesta() {
    // Accumulate a small batch.
    let mut acc = SplitAccumulator::<FrVesta>::new();
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..5 {
        acc.push(Accumulator::unit(FrVesta::random(&mut rng)));
    }
    let folded = acc.split_fold().v;

    // State transition: new = old + meta * folded
    let old = FrVesta::random(&mut rng);
    let meta = FrVesta::random(&mut rng);
    let new = old + meta * folded;

    let data = PcdData { old_root: old, new_root: new, metadata: meta, accumulator: folded };

    let backend = TranscriptBackend;
    let circuit = Noop;
    let driver = CpuDriver::<FrVesta>::new();

    let proof: Pcd<FrVesta, _> = prove_step(&backend, &circuit, driver, None, data.clone()).unwrap();
    verify_step(&backend, &proof).unwrap();

    // Instance alignment
    let expected = Instance { inputs: vec![old, new, meta, folded] };
    assert_eq!(proof.instance.inputs, expected.inputs);
}

#[test]
fn nested_cycle_types_compile() {
    // Just exercise both fields.
    let a = FrPallas::ONE + FrPallas::ONE;
    let b = FrVesta::ONE + FrVesta::ONE;
    assert!(bool::from(a.ct_eq(&FrPallas::from(2u64))));
    assert!(bool::from(b.ct_eq(&FrVesta::from(2u64))));
}


