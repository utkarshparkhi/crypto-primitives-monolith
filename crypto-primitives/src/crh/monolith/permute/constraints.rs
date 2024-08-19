use core::ops::AddAssign;

use super::mds_12;
use crate::crh::monolith::fields::goldilocks::Fr as FP64;
use crate::crh::monolith::fields::goldilocks::FrConfig;
use crate::crh::monolith::MonolithParams;
use ark_ff::MontBackend;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
pub struct MonolithPermuteVar<const T: usize>;
impl<const T: usize> MonolithPermuteVar<T> {
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn s(&self, byt: UInt8<FP64>) -> Result<UInt8<FP64>, SynthesisError> {
        let b1 = !byt.rotate_left(1);
        let b2 = byt.rotate_left(2);
        let b3 = byt.rotate_left(3);
        let b = byt.clone() ^ (b1 & b2 & b3);
        Ok(b.rotate_left(1))
    }
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn bar(&self, element: FpVar<FP64>) -> Result<FpVar<FP64>, SynthesisError> {
        let mut byts = <FpVar<FP64> as ToBytesGadget<_>>::to_bytes_le(&element)?;
        for byt in &mut byts {
            *byt = self.s(byt.clone())?;
        }
        let ele = Boolean::le_bits_to_fp(byts.to_bits_le()?.as_slice())?;
        Ok(ele)
        // let mut bts = <FpVar<FP64> as ToBitsGadget<_>>::to_bits_le(&element)?;
        // let l1
        // let rot1_1 = Boolean::<FP64>::constant_vec_from_bytes(&0x8080808080808080u64.to_le_bytes());
        // let rot1_2 = Boolean::<FP64>::constant_vec_from_bytes(&0x7F7F7F7F7F7F7F7Fu64.to_le_bytes());
        // let rot2_1 = Boolean::<FP64>::constant_vec_from_bytes(&0xC0C0C0C0C0C0C0C0u64.to_le_bytes());
        // let rot2_2 = Boolean::<FP64>::constant_vec_from_bytes(&0x3F3F3F3F3F3F3F3Fu64.to_le_bytes());
        // let limb1: Vec<Boolean<FP64>> = bts.iter().zip(rot1_1).map(|(b, r)| b & r).collect();
        // Ok(FpVar::<FP64>::zero())
    }
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn bars(
        &self,
        input: [FpVar<FP64>; T],
        params: MonolithParams,
    ) -> Result<[FpVar<FP64>; T], SynthesisError> {
        let mut out_bars: Vec<FpVar<FP64>> = vec![];
        for (ind, ele) in input.iter().enumerate().into_iter() {
            if ind >= params.bar_per_round.into() {
                out_bars.push(ele.clone());
                continue;
            }

            out_bars.push(self.bar(ele.clone()).expect("Err"));
        }
        Ok(out_bars.try_into().unwrap())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn bricks(&self, input: &mut [FpVar<FP64>]) -> Result<(), SynthesisError> {
        for i in (1..input.len()).rev() {
            let m = input[i - 1].square().expect("Err");
            input[i].add_assign(m);
        }
        Ok(())
    }
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn concrete(&self, input: &mut [FpVar<FP64>]) -> Result<(), SynthesisError> {
        if T == 12 {
            let row = [7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8];
            let mds = mds_12::circ_mat::<MontBackend<FrConfig, 1>>(&row);
            let mut out = Vec::new();
            for row in 0..T {
                let mut cur = FpVar::<FP64>::zero();
                for (col, inp) in input.iter().enumerate().take(T) {
                    let term = inp * mds[row][col];
                    cur += term;
                }
                out.push(cur);
            }
            input.clone_from_slice(&out[..T])
        }
        Ok(())
    }
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn concrete_wrc(
        &self,
        input: &mut [FpVar<FP64>],
        round_constants: &[FP64],
    ) -> Result<(), SynthesisError> {
        if T == 12 {
            let row = [7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8];
            let mds = mds_12::circ_mat::<MontBackend<FrConfig, 1>>(&row);
            let mut out = Vec::new();
            for row in 0..T {
                let mut cur = FpVar::<FP64>::zero();
                cur += round_constants[row];
                for (col, inp) in input.iter().enumerate().take(T) {
                    let term = inp * mds[row][col];
                    cur += term;
                }
                out.push(cur);
            }
            input.clone_from_slice(&out[..T]);
        }
        Ok(())
    }
    pub fn permute(
        &self,
        input: &mut [FpVar<FP64>],
        params: &MonolithParams,
    ) -> Result<(), SynthesisError> {
        println!("Permute INP CIRC: {:?}", input.value().unwrap());
        println!("cons before permute: {:?}", input.cs().num_constraints());
        let mut out: [FpVar<FP64>; T] = input
            .to_vec()
            .try_into()
            .expect("array size does not match");
        self.concrete(&mut out)?;
        println!("cons aft fconc: {:?}", out.cs().num_constraints());
        for rc in params.round_constants.iter() {
            out = self.bars(out, params.clone())?;
            println!("cons aft bar: {:?}", out.cs().num_constraints());
            self.bricks(&mut out)?;
            println!("cons aft bri: {:?}", out.cs().num_constraints());
            self.concrete_wrc(&mut out, rc)?;
            println!("cons aft conc: {:?}", out.cs().num_constraints());
        }
        input.clone_from_slice(&out[..T]);
        println!("cons after permute: {:?}", input.cs().num_constraints());
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::crh::monolith::permute::MonolithPermute;
    use crate::crh::{monolith::CRH64, CRHScheme};
    use ark_ff::UniformRand;
    use rand::thread_rng;
    #[test]
    pub fn simple_permute() {
        let mut rng = thread_rng();
        let mut inp: [FP64; 12] = [FP64::rand(&mut rng); 12];
        let mut inp_var: [FpVar<FP64>; 12] = [
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
            FpVar::<FP64>::zero() + inp[0],
        ];
        let params = CRH64::<12>::setup(&mut rng).unwrap();
        MonolithPermute::<12>::permute(&mut inp, &params);
        let v = MonolithPermuteVar::<12>;
        let _ = v.permute(&mut inp_var, &params);
        assert_eq!(inp_var.value(), Ok(inp));
    }
}
