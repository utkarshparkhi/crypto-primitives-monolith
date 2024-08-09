#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod fields;
pub mod permute;
use std::usize;

use crate::crh::monolith::fields::goldilocks::Fr as F64;
use crate::crh::CRHScheme;
use crate::sponge::generic::generic_sponge::MonolithSponge;
use crate::sponge::generic::generic_sponge::SpongeConfig;
use crate::sponge::CryptographicSponge;
use crate::Error;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Read;
use ark_std::marker::PhantomData;
use sha3::digest::ExtendableOutput;
use sha3::digest::Update;
use sha3::Shake128;
use sha3::Shake128Reader;

use self::permute::MonolithPermute;

use super::TwoToOneCRHScheme;
pub struct CRH64<const T: usize> {
    field_phantom: PhantomData<F64>,
}
pub struct TwoToOneCrhScheme64 {
    field_phantom: PhantomData<F64>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct MonolithParams {
    bar_per_round: u8,
    rounds: u8,
    state_size: u32,
    pub round_constants: Vec<Vec<F64>>,
}

impl<const Y: usize> CRHScheme for CRH64<Y> {
    type Input = [F64];
    type Output = F64;
    type Parameters = MonolithParams;
    fn setup<R: ark_std::rand::prelude::Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        let rounds: u8 = 6;
        let state_size: u32 = Y.try_into().expect("Failed to convert field to u32");
        let mut round_constants: Vec<Vec<F64>> = vec![];
        let mut shake = Shake128::default();
        shake.update(b"Monolith");
        shake.update(&[Y as u8, rounds]);
        shake.update(&F64::MODULUS.to_bytes_le());
        shake.update(&[8, 8, 8, 8, 8, 8, 8, 8]);
        let mut shake_reader: Shake128Reader = shake.finalize_xof();
        while round_constants.len() + 1 < rounds.into() {
            let mut rands: Vec<F64> = vec![];
            loop {
                let mut rng = [0u8; 8];
                shake_reader
                    .read(&mut rng)
                    .expect("Failed to generate random number");
                let ele = <F64 as Field>::from_random_bytes(&rng);
                if ele.is_some() {
                    rands.push(ele.unwrap());
                }
                if rands.len() == Y {
                    break;
                }
            }
            round_constants.push(rands);
        }
        let last_rc = [<F64 as Zero>::zero(); Y];
        round_constants.push(last_rc.to_vec());
        Ok(MonolithParams {
            bar_per_round: 4,
            rounds,
            state_size,
            round_constants,
        })
    }
    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();
        let sponge_params = SpongeConfig::new(8, 4, parameters);
        let mut sponge = MonolithSponge::new(&sponge_params);
        sponge.absorb(&input);
        let res = sponge.squeeze_field_elements::<F64>(1);
        // let mut outp = [F64::zero(); 4];
        // outp.copy_from_slice(&res);
        Ok(res[0])
    }
}

impl TwoToOneCRHScheme for TwoToOneCrhScheme64 {
    type Input = [F64; 4];
    type Output = [F64; 4];
    type Parameters = MonolithParams;
    fn setup<R: rand::prelude::Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        let rounds: u8 = 6;
        let state_size: u32 = 8;
        let mut round_constants: Vec<Vec<F64>> = vec![];
        let mut shake = Shake128::default();
        shake.update(b"Monolith");
        shake.update(&[state_size as u8, rounds]);
        shake.update(&F64::MODULUS.to_bytes_le());
        shake.update(&[8, 8, 8, 8, 8, 8, 8, 8]);
        let mut shake_reader: Shake128Reader = shake.finalize_xof();
        while round_constants.len() + 1 < rounds.into() {
            let mut rands: Vec<F64> = vec![];
            loop {
                let mut rng = [0u8; 8];
                shake_reader
                    .read(&mut rng)
                    .expect("Failed to generate random number");
                let ele = <F64 as Field>::from_random_bytes(&rng);
                if ele.is_some() {
                    rands.push(ele.unwrap());
                }
                if rands.len() == state_size as usize {
                    break;
                }
            }
            round_constants.push(rands);
        }
        let last_rc = [<F64 as Zero>::zero(); 8];
        round_constants.push(last_rc.to_vec());
        Ok(MonolithParams {
            bar_per_round: 4,
            rounds,
            state_size,
            round_constants,
        })
    }
    fn evaluate<T: core::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::compress(parameters, left_input, right_input)
    }
    fn compress<T: core::borrow::Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let mut inp: [F64; 8] = [F64::zero(); 8];

        inp[..4].copy_from_slice(&left_input.borrow()[..4]);
        inp[4..].copy_from_slice(&right_input.borrow()[..4]);
        let mut out: [F64; 4] = *left_input.borrow();
        MonolithPermute::<8>::permute(&mut inp, parameters);
        for i in 0..4 {
            out[i] += inp[i];
        }
        Ok(out)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    // use crate::crh::sha256::Sha256;
    use ark_ff::UniformRand;
    // use ark_std::iterable::Iterable;
    use ark_std::test_rng;
    use std::time::Instant;
    #[test]
    pub fn crh_mono_hash() {
        let mut rng = test_rng();
        let input = [
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
        ];
        let now = Instant::now();
        let params = CRH64::<12>::setup(&mut rng).unwrap();
        let out = CRH64::<12>::evaluate(&params, input);
        let elapsed = now.elapsed();
        // let mut inp = Vec::new();
        // for ele in input.iter() {
        //     inp.extend(ele.into_bigint().to_bytes_le());
        // }
        // let now = Instant::now();
        // let params = <Sha256 as CRHScheme>::setup(&mut rng).unwrap();
        // let out = <Sha256 as CRHScheme>::evaluate(&params, inp.clone());
        // let elapsed = now.elapsed();
        // println!("inp: {:?}", inp);
        println!("inp: {:?}", input);
        println!("out: {:?}", out);
        println!("Elapsed: {:.2?}", elapsed);
    }
    #[test]
    pub fn two_to_one_mono_hash() {
        let mut rng = test_rng();
        let left_input = [
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
        ];
        let right_input = [
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
            F64::rand(&mut rng),
        ];
        println!("inp: {:?},{:?}", left_input, right_input);

        let params = TwoToOneCrhScheme64::setup(&mut rng).unwrap();
        let now = Instant::now();
        let out = TwoToOneCrhScheme64::evaluate(&params, left_input, right_input);
        let elapsed = now.elapsed();
        println!("out: {:?}", out);
        println!("Elapsed: {:.2?}", elapsed);
    }
}
