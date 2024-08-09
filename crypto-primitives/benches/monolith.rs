#[macro_use]
extern crate criterion;
use ark_std::rand::Rng;

use ark_crypto_primitives::crh::monolith::fields::goldilocks::Fr as F64;
use ark_crypto_primitives::crh::monolith::permute::{self, MonolithPermute};
use ark_crypto_primitives::crh::monolith::CRH64;
use ark_crypto_primitives::crh::CRHScheme;
use ark_std::UniformRand;
use criterion::Criterion;

fn monolith_eval(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let params = CRH64::<12>::setup(rng).unwrap();

    let input = [
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
        F64::rand(rng),
    ];
    c.bench_function("Monolith CRH Eval", move |b| {
        b.iter(|| CRH64::<12>::evaluate(&params, input).unwrap())
    });
    // let mut inp: [u8; 96] = [0; 96];
    // inp[..32].copy_from_slice(&inp1[..]);
    // inp[32..64].copy_from_slice(&inp2[..]);
    //
    // inp[64..].copy_from_slice(&inp3[..]);
    // let par = <Sha256 as CRHScheme>::setup(rng).unwrap();
    // c.bench_function("Sha 256 CRH Eval", move |b| {
    //     b.iter(|| <Sha256 as CRHScheme>::evaluate(&par, inp).unwrap())
    // });
}
fn monolith_permute(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let params = CRH64::<12>::setup(rng).unwrap();
    let mut input: [F64; 12] = rng.gen();
    c.bench_function("Monolith Permute", move |b| {
        b.iter(|| MonolithPermute::<12>::permute(&mut input, &params))
    });
}
criterion_group! {
    name = monolith_hash;
    config = Criterion::default().sample_size(10);
    targets = monolith_eval
}
criterion_group! {
    name = monolith_perm;
    config = Criterion::default().sample_size(10);
    targets = monolith_permute
}

criterion_main!(monolith_perm, monolith_hash);
