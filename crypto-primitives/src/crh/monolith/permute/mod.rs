use std::usize;

use crate::crh::monolith::fields::goldilocks::{Fr as F64, FrConfig};
use crate::crh::monolith::MonolithParams;
use ark_ff::BigInteger;
use ark_ff::MontBackend;
use ark_ff::PrimeField;
use ark_ff::Zero;
use std::time::Instant;

mod mds_12;
mod mds_8;

pub struct MonolithPermute<const T: usize>;
impl<const T: usize> MonolithPermute<T> {
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
    pub fn concrete_wrc_u128(input: &mut [u128; T], round_constant: &[F64]) {
        if T == 8 {
            mds_8::mds_multiply_with_rc_u128::<MontBackend<FrConfig, 1>>(
                input
                    .as_mut()
                    .try_into()
                    .expect("incorrect input size for mds"),
                round_constant
                    .try_into()
                    .expect("incorrect input size of round constants"),
            );
        } else if T == 12 {
            mds_12::mds_multiply_with_rc_u128::<MontBackend<FrConfig, 1>>(
                input
                    .as_mut()
                    .try_into()
                    .expect("incorrect input size for mds"),
                round_constant
                    .try_into()
                    .expect("incorrect input size of round constants"),
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
    pub fn concrete_u128(input: &mut [u128; T]) {
        if T == 8 {
            mds_8::mds_multiply_u128::<MontBackend<FrConfig, 1>>(
                input
                    .as_mut()
                    .try_into()
                    .expect("incorrect input size for mds"),
            );
        } else if T == 12 {
            mds_12::mds_multiply_u128::<MontBackend<FrConfig, 1>>(
                input
                    .as_mut()
                    .try_into()
                    .expect("incorrect input size for mds"),
            );
        }
    }
    pub fn permute(input: &mut [F64], params: &MonolithParams) {
        let now = Instant::now();
        let mut inp: [F64; T] = [F64::zero(); T];
        inp.copy_from_slice(input);
        Self::concrete(&mut inp);

        for rc in params.round_constants.iter() {
            Self::bars(&mut inp, params);
            Self::bricks(&mut inp);
            Self::concrete_wrc(&mut inp, rc);
        }
        input.copy_from_slice(&inp);
        let elapsed = now.elapsed();
        println!("Elapsed permute: {:.2?}", elapsed);
    }
}
