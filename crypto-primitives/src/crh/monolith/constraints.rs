use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{ToBytesGadget, UInt8};
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystemRef;
use core::marker::PhantomData;
use core::usize;

use crate::crh::monolith::fields::goldilocks::Fr as FP64;
use crate::crh::monolith::MonolithParams;
use crate::crh::monolith::TwoToOneCrhScheme64;
use crate::crh::monolith::CRH64;
use crate::crh::CRHScheme;
use crate::crh::CRHSchemeGadget;
use crate::crh::TwoToOneCRHScheme;
use crate::crh::TwoToOneCRHSchemeGadget;
use crate::sponge::constraints::CryptographicSpongeVar;
use crate::sponge::generic::constraints::MonolithSpongeVar;
use crate::sponge::generic::generic_sponge::SpongeConfig;

use super::permute::constraints::MonolithPermuteVar;
// #[derive(Debug, Clone)]
// struct VecFPVar(Vec<FpVar<FP64>>);
// impl AllocVar<Vec<FP64>, FP64> for VecFPVar {
//     fn new_variable<T: Borrow<Vec<FP64>>>(
//         cs: impl Into<ark_relations::r1cs::Namespace<FP64>>,
//         f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
//         mode: AllocationMode,
//     ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
//         let ns = cs.into();
//         let cs = ns.cs();
//
//         let values = f()?.borrow().clone();
//
//         let mut vars = Vec::new();
//         for val in values {
//             let var = FpVar::new_variable(cs.clone(), || Ok(val), mode)?;
//             vars.push(var);
//         }
//
//         Ok(VecFPVar(vars))
//     }
// }
// impl CondSelectGadget<FP64> for VecFPVar {
//     fn conditionally_select(
//         cond: &Boolean<FP64>,
//         true_value: &Self,
//         false_value: &Self,
//     ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
//         // Ensure the lengths of both vectors are equal
//         assert_eq!(true_value.0.len(), false_value.0.len());
//
//         let mut selected_vars = Vec::with_capacity(true_value.0.len());
//         for (true_var, false_var) in true_value.0.iter().zip(false_value.0.iter()) {
//             // Perform element-wise conditional selection
//             let selected_var = FpVar::conditionally_select(cond, true_var, false_var)?;
//             selected_vars.push(selected_var);
//         }
//
//         Ok(VecFPVar(selected_vars))
//     }
// }
//
//
#[derive(Clone, Debug)]
pub struct VecFpVar {
    pub vars: Vec<FpVar<FP64>>,
}

impl AllocVar<Vec<FP64>, FP64> for VecFpVar {
    fn new_variable<T: std::borrow::Borrow<Vec<FP64>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<FP64>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let values = f()?.borrow().clone();
        let mut vars = Vec::new();
        for value in values {
            let var = FpVar::new_variable(cs.clone(), || Ok(value), mode)?;
            vars.push(var);
        }
        Ok(VecFpVar { vars })
    }
}

impl EqGadget<FP64> for VecFpVar {
    fn is_eq(&self, other: &Self) -> Result<Boolean<FP64>, ark_relations::r1cs::SynthesisError> {
        assert_eq!(self.vars.len(), other.vars.len());
        let mut result = Boolean::constant(true);
        for (a, b) in self.vars.iter().zip(other.vars.iter()) {
            let eq = a.is_eq(b)?;
            result = result & (&eq);
        }
        Ok(result)
    }
}

impl CondSelectGadget<FP64> for VecFpVar {
    fn conditionally_select(
        cond: &Boolean<FP64>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        assert_eq!(true_value.vars.len(), false_value.vars.len());
        let mut selected_vars = Vec::new();
        for (t, f) in true_value.vars.iter().zip(false_value.vars.iter()) {
            let var = FpVar::conditionally_select(cond, t, f)?;
            selected_vars.push(var);
        }
        Ok(VecFpVar {
            vars: selected_vars,
        })
    }
}

impl ToBytesGadget<FP64> for VecFpVar {
    fn to_bytes_le(&self) -> Result<Vec<UInt8<FP64>>, ark_relations::r1cs::SynthesisError> {
        Vec::<_>::to_bytes_le(&self.vars)
    }
}

impl R1CSVar<FP64> for VecFpVar {
    type Value = Vec<FP64>;

    fn cs(&self) -> ConstraintSystemRef<FP64> {
        let mut result = ConstraintSystemRef::None;
        for var in self.vars.iter() {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, ark_relations::r1cs::SynthesisError> {
        let mut result = Vec::new();
        for var in self.vars.iter() {
            result.push(var.value()?);
        }
        Ok(result)
    }
}
#[derive(Clone)]
pub struct CRHParametersVar {
    pub parameters: MonolithParams,
}
pub struct CRHGadget<const T: usize> {
    field_phantom: PhantomData<FP64>,
}

impl AllocVar<MonolithParams, FP64> for CRHParametersVar {
    fn new_variable<T: core::borrow::Borrow<MonolithParams>>(
        _cs: impl Into<ark_relations::r1cs::Namespace<FP64>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        f().and_then(|param| {
            let params = param.borrow().clone();
            Ok(Self { parameters: params })
        })
    }
}
impl<const T: usize> CRHSchemeGadget<CRH64<T>, FP64> for CRHGadget<T> {
    type InputVar = [FpVar<FP64>];
    type OutputVar = VecFpVar;
    type ParametersVar = CRHParametersVar;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let cs = input.cs();

        if cs.is_none() {
            let mut constant_input = Vec::new();
            for var in input.iter() {
                constant_input.push(var.value().unwrap());
            }
            let hsh: Vec<FP64> =
                CRH64::<12>::evaluate(&parameters.parameters, constant_input).unwrap();
            let mut c_hsh: Vec<FpVar<FP64>> = vec![];
            for val in hsh.iter() {
                c_hsh.push(FpVar::<_>::new_constant(cs.clone(), val)?);
            }
            Ok(VecFpVar { vars: c_hsh })
        } else {
            let sponge_config = SpongeConfig::new(8, 4, &parameters.parameters);
            let mut sponge = MonolithSpongeVar::new(cs, &sponge_config);

            sponge.absorb(&input).unwrap();
            let res = sponge.squeeze_field_elements(4).unwrap();
            Ok(VecFpVar { vars: res })
        }
    }
}
pub struct TwoToOneCRHGadget {
    field_phantom: PhantomData<FP64>,
}
impl TwoToOneCRHSchemeGadget<TwoToOneCrhScheme64, FP64> for TwoToOneCRHGadget {
    type InputVar = VecFpVar;
    type OutputVar = VecFpVar;
    type ParametersVar = CRHParametersVar;
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Self::compress(parameters, &left_input, &right_input)
    }
    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let cs = left_input.cs().or(right_input.cs());
        if cs.is_none() {
            let outp = TwoToOneCrhScheme64::evaluate(
                &parameters.parameters,
                left_input.value()?,
                right_input.value()?,
            )
            .unwrap();

            Ok(VecFpVar {
                vars: vec![
                    FpVar::Constant(outp[0]),
                    FpVar::Constant(outp[1]),
                    FpVar::Constant(outp[2]),
                    FpVar::Constant(outp[3]),
                ],
            })
        } else {
            let outp = VecFpVar {
                vars: left_input.vars.clone(),
            };
            let mut inp: Vec<FpVar<FP64>> = vec![];
            for val in left_input.vars.iter() {
                inp.push(val.clone());
            }
            for val in right_input.vars.iter() {
                inp.push(val.clone());
            }
            let permute_var = MonolithPermuteVar::<8>;
            permute_var.permute(inp.as_mut_slice(), &parameters.parameters)?;
            let outp = VecFpVar {
                vars: outp
                    .vars
                    .iter()
                    .zip(inp.clone())
                    .map(|(x, y)| x + y)
                    .collect(),
            };
            Ok(outp)
        }
    }
}
#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::iterable::Iterable;

    use crate::crh::monolith::constraints::CRHGadget;
    use crate::crh::monolith::constraints::CRHParametersVar;
    use crate::crh::monolith::constraints::TwoToOneCRHGadget;
    use crate::crh::monolith::constraints::TwoToOneCrhScheme64;
    use crate::crh::monolith::fields::goldilocks::Fr as FP64;
    use crate::crh::monolith::CRH64;
    use crate::crh::TwoToOneCRHScheme;
    use crate::crh::TwoToOneCRHSchemeGadget;
    use crate::crh::{CRHScheme, CRHSchemeGadget};

    use super::VecFpVar;
    #[test]
    fn test_consistency() {
        let mut test_rng = ark_std::test_rng();
        let monolith_params = CRH64::<12>::setup(&mut test_rng).unwrap();
        let inp = [
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
            // FP64::rand(&mut test_rng),
        ];
        let cs = ConstraintSystem::<FP64>::new_ref();
        let mut inp_var = [
            FpVar::<FP64>::zero(),
            FpVar::<FP64>::zero(),
            FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
            // FpVar::<FP64>::zero(),
        ];
        for i in 0..inp.len() {
            inp_var[i] =
                FpVar::new_witness(cs.clone(), || Ok(inp[i].clone())).expect("inp var failed");
        }
        println!("inp : {:?}", inp);
        println!("inp_var: {:?}", inp_var.value().unwrap());
        let params_var =
            CRHParametersVar::new_witness(cs.clone(), || Ok(monolith_params.clone())).unwrap();
        let outp_var = CRHGadget::<12>::evaluate(&params_var, &inp_var).unwrap();
        let outp = CRH64::<12>::evaluate(&monolith_params, inp).unwrap();
        println!("num constraints: {:?}", cs.num_constraints());
        assert_eq!(outp, outp_var.value().unwrap())
    }
    #[test]
    fn test_consistency_two() {
        let mut test_rng = ark_std::test_rng();
        let monolith_params = TwoToOneCrhScheme64::setup(&mut test_rng).unwrap();
        let inp1 = vec![
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
        ];
        let inp2 = vec![
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
            FP64::rand(&mut test_rng),
        ];
        let mut inp1_var = vec![];
        let mut inp2_var = vec![];
        let cs = ConstraintSystem::<FP64>::new_ref();
        // cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
        for val in inp1.iter() {
            inp1_var.push(
                FpVar::<FP64>::new_witness(cs.clone(), || Ok(val.clone())).expect("inp var failed"),
            );
        }
        for val in inp2.iter() {
            inp2_var.push(
                FpVar::<FP64>::new_witness(cs.clone(), || Ok(val.clone())).expect("inp var failed"),
            );
        }
        let params_var = CRHParametersVar::new_witness(cs.clone(), || Ok(monolith_params.clone()))
            .expect("param var failed");
        let outp = TwoToOneCrhScheme64::evaluate(&monolith_params, inp1, inp2).unwrap();
        let outp_var = <TwoToOneCRHGadget as TwoToOneCRHSchemeGadget<_, _>>::compress(
            &params_var,
            &VecFpVar { vars: inp1_var },
            &VecFpVar { vars: inp2_var },
        )
        .unwrap();
        cs.finalize();
        // println!("A: {:?}", cs.to_matrices().unwrap().a);
        // println!("B: {:?}", cs.to_matrices().unwrap().b);
        // println!("C: {:?}", cs.to_matrices().unwrap().c);
        println!("num cons: {:?}", cs.num_constraints());
        println!("outp: {:?}", outp);
        println!("outp_var: {:?}", outp_var.vars.value().unwrap());
        assert_eq!(outp, outp_var.vars.value().unwrap());
    }
}
