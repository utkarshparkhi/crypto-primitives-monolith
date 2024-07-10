use std::usize;

use crate::crh::monolith::fields::goldilocks::Fr as F64;
use crate::crh::monolith::mds_12;
use crate::crh::monolith::mds_8;
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
pub struct CRH64<const T: usize> {
    field_phantom: PhantomData<F64>,
}
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct MonolithParams {
    bar_per_round: u8,
    rounds: u8,
    state_size: u32,
    pub round_constants: Vec<Vec<F64>>,
}
impl<const T: usize> CRH64<T> {
    pub fn s(byt: u8) -> u8 {
        (byt ^ (!byt.rotate_left(1) & byt.rotate_left(2) & byt.rotate_left(3))).rotate_left(1)
    }
    pub fn bar(element: F64) -> F64 {
        let mut be_bytes = element.into_bigint().to_bytes_be();
        for byt in &mut be_bytes {
            *byt = Self::s(*byt);
        }
        <F64 as PrimeField>::from_be_bytes_mod_order(&be_bytes)
    }
    pub fn bars(input: &mut [F64; T], params: &MonolithParams) {
        let mut out_bars: Vec<_> = vec![];
        for (ind, ele) in input.iter().enumerate().into_iter() {
            if ind >= params.bar_per_round.into() {
                out_bars.push(*ele);
                continue;
            }
            out_bars.push(Self::bar(*ele));
        }
        input.copy_from_slice(&out_bars[..]);
    }
    pub fn bricks(input: &mut [F64; T]) {
        for i in (1..input.len()).rev() {
            input[i] += input[i - 1] * input[i - 1];
        }
    }
    pub fn concrete_wrc(input: &mut [F64; T], round_constant: &[F64]) {
        if T == 8 {
            mds_8::mds_multiply_with_rc(
                input.as_mut().try_into().unwrap(),
                round_constant.try_into().unwrap(),
            );
        } else if T == 12 {
            mds_12::mds_multiply_with_rc(
                input.as_mut().try_into().unwrap(),
                round_constant.try_into().unwrap(),
            );
        }
    }
    pub fn concrete(input: &mut [F64; T]) {
        if T == 8 {
            mds_8::mds_multiply(input.as_mut().try_into().unwrap());
        } else if T == 12 {
            mds_12::mds_multiply(input.as_mut().try_into().unwrap());
        }
    }
    pub fn permute(input: &mut [F64], params: &MonolithParams) {
        let mut inp: [F64; T] = [F64::zero(); T];
        inp.copy_from_slice(input);
        Self::concrete(&mut inp);

        for rc in params.round_constants.iter() {
            Self::bars(&mut inp, params);
            Self::bricks(&mut inp);
            Self::concrete_wrc(&mut inp, rc);
        }
        input.copy_from_slice(&inp)
    }
}
impl<const Y: usize> CRHScheme for CRH64<Y> {
    type Input = [F64];
    type Output = [F64; 4];
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
        let mut sponge = MonolithSponge::<F64>::new(&sponge_params);
        sponge.absorb(&input);
        let res = sponge.squeeze_field_elements::<F64>(4);
        let mut outp = [F64::zero(); 4];
        outp.copy_from_slice(&res);
        Ok(outp)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::crh::monolith::fields::goldilocks::Fr as FP64;
    use ark_std::One;
    use rand::thread_rng;
    #[test]
    pub fn hash() {
        let input = [
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
            <FP64 as One>::one(),
        ];
        let mut rng = thread_rng();

        let params = CRH64::<12>::setup(&mut rng).unwrap();
        let out = CRH64::<12>::evaluate(&params, input);
        println!("inp: {:?}", input);
        println!("out: {:?}", out)
    }
}
