use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use core::marker::PhantomData;
use core::usize;

use crate::crh::monolith::fields::goldilocks::Fr as FP64;
use crate::crh::monolith::MonolithParams;
use crate::crh::monolith::CRH64;
use crate::crh::CRHScheme;
use crate::crh::CRHSchemeGadget;
use crate::sponge::constraints::CryptographicSpongeVar;
use crate::sponge::generic::constraints::MonolithSpongeVar;
use crate::sponge::generic::generic_sponge::SpongeConfig;
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
    type OutputVar = FpVar<FP64>;
    type ParametersVar = CRHParametersVar;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let cs = input.cs();

        if cs.is_none() {
            let mut constant_input = Vec::new();
            for var in input.iter() {
                constant_input.push(var.value()?);
            }
            let hsh = CRH64::<12>::evaluate(&parameters.parameters, constant_input).unwrap();

            Ok(FpVar::Constant(hsh))
        } else {
            let sponge_config = SpongeConfig::new(8, 4, &parameters.parameters);
            let mut sponge = MonolithSpongeVar::new(cs, &sponge_config);

            sponge.absorb(&input)?;
            let res = sponge.squeeze_field_elements(1)?;
            Ok(res[0].clone())
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
    use crate::crh::monolith::fields::goldilocks::Fr as FP64;
    use crate::crh::monolith::CRH64;
    use crate::crh::{CRHScheme, CRHSchemeGadget};
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
}
