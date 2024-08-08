use std::usize;

use crate::crh::monolith::fields::goldilocks::{Fr as F64, FrConfig};
use crate::crh::monolith::MonolithParams;
use ark_ff::Field;
use ark_ff::MontBackend;
use ark_ff::Zero;
use ark_ff::{BigInteger64, PrimeField};

mod mds_12;
mod mds_8;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct MonolithPermute<const T: usize>;
impl<const T: usize> MonolithPermute<T> {
    // pub fn s(byt: u8) -> u8 {
    //     (byt ^ (!byt.rotate_left(1) & byt.rotate_left(2) & byt.rotate_left(3))).rotate_left(1)
    // }
    pub fn bar(element: F64) -> F64 {
        // let mut le_bytes = element.into_bigint().to_bytes_le();
        // for byt in &mut le_bytes {
        //     *byt = Self::s(*byt);
        // }
        let mut ele: u64 = element.into_bigint().0[0];
        let limbl1 = ((ele & 0x8080808080808080) >> 7) | ((ele & 0x7F7F7F7F7F7F7F7F) << 1); //left rot by 1
        let limbl2 = ((ele & 0xC0C0C0C0C0C0C0C0) >> 6) | ((ele & 0x3F3F3F3F3F3F3F3F) << 2); //left rot by 2
        let limbl3 = ((ele & 0xE0E0E0E0E0E0E0E0) >> 5) | ((ele & 0x1F1F1F1F1F1F1F1F) << 3); //left rot by 3
        ele = ele ^ (!limbl1 & limbl2 & limbl3);
        ele = ele.rotate_left(1);
        // le_bytes.iter_mut().for_each(|byt| *byt = Self::s(*byt));
        <F64 as PrimeField>::from_bigint(BigInteger64::from(ele)).unwrap()
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
            input[i] += input[i - 1].square();
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
        let mut inp: [F64; T] = [F64::zero(); T];
        inp.copy_from_slice(input);
        Self::concrete(&mut inp);

        for rc in params.round_constants.iter() {
            Self::bars(&mut inp, params);
            Self::bricks(&mut inp);
            Self::concrete_wrc(&mut inp, rc);
        }
        input.copy_from_slice(&inp);
    }
}
