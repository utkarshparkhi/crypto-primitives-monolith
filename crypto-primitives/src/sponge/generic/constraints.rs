use crate::crh::monolith::fields::goldilocks::Fr as FP64;
use crate::crh::monolith::permute::constraints::MonolithPermuteVar;
use crate::sponge::constraints::AbsorbGadget;
use crate::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use crate::sponge::DuplexSpongeMode;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

use super::generic_sponge::{MonolithSponge, SpongeConfig};

#[derive(Clone)]
/// the gadget for Poseidon sponge
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct MonolithSpongeVar {
    /// Constraint system
    pub cs: ConstraintSystemRef<FP64>,

    /// Sponge Parameters
    pub parameters: SpongeConfig,

    // Sponge State
    /// The sponge's state
    pub state: Vec<FpVar<FP64>>,
    /// The mode
    pub mode: DuplexSpongeMode,
}

impl SpongeWithGadget<FP64> for MonolithSponge<FP64> {
    type Var = MonolithSpongeVar;
}

impl MonolithSpongeVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn permute(&mut self) -> Result<(), SynthesisError> {
        let mono_permute_var = MonolithPermuteVar::<12>;
        mono_permute_var.permute(&mut self.state, &self.parameters.params)?;
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn absorb_internal(
        &mut self,
        mut rate_start_index: usize,
        elements: &[FpVar<FP64>],
    ) -> Result<(), SynthesisError> {
        let mut remaining_elements = elements;
        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.parameters.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.parameters.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return Ok(());
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.parameters.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.parameters.capacity + i + rate_start_index] += element;
            }
            self.permute()?;
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_internal(
        &mut self,
        mut rate_start_index: usize,
        output: &mut [FpVar<FP64>],
    ) -> Result<(), SynthesisError> {
        let mut remaining_output = output;
        loop {
            // if we can finish in this call
            if rate_start_index + remaining_output.len() <= self.parameters.rate {
                remaining_output.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + remaining_output.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + remaining_output.len(),
                };
                return Ok(());
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            remaining_output[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Unless we are done with squeezing in this call, permute.
            if remaining_output.len() != self.parameters.rate {
                self.permute()?;
            }
            // Repeat with updated output slices and rate start index
            remaining_output = &mut remaining_output[num_elements_squeezed..];
            rate_start_index = 0;
        }
    }
}

impl CryptographicSpongeVar<FP64, MonolithSponge<FP64>> for MonolithSpongeVar {
    type Parameters = SpongeConfig;

    #[tracing::instrument(target = "r1cs", skip(cs))]
    fn new(cs: ConstraintSystemRef<FP64>, parameters: &SpongeConfig) -> Self {
        let zero = FpVar::<FP64>::zero();
        let state = vec![zero; parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            cs,
            parameters: parameters.clone(),
            state,
            mode,
        }
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn cs(&self) -> ConstraintSystemRef<FP64> {
        self.cs.clone()
    }

    #[tracing::instrument(target = "r1cs", skip(self, input))]
    fn absorb(&mut self, input: &impl AbsorbGadget<FP64>) -> Result<(), SynthesisError> {
        let input = input.to_sponge_field_elements()?;
        if input.is_empty() {
            return Ok(());
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.parameters.rate {
                    self.permute()?;
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, input.as_slice())?;
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.permute()?;
                self.absorb_internal(0, input.as_slice())?;
            }
        };

        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<FP64>>, SynthesisError> {
        let usable_bytes = ((FP64::MODULUS_BIT_SIZE - 1) / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bytes: Vec<UInt8<FP64>> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            bytes.extend_from_slice(&elem.to_bytes_le()?[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        Ok(bytes)
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<FP64>>, SynthesisError> {
        let usable_bits = (FP64::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = (num_bits + usable_bits - 1) / usable_bits;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bits: Vec<Boolean<FP64>> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
        }

        bits.truncate(num_bits);
        Ok(bits)
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<FP64>>, SynthesisError> {
        let zero = FpVar::zero();
        let mut squeezed_elems = vec![zero; num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute()?;
                self.squeeze_internal(0, &mut squeezed_elems)?;
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.parameters.rate {
                    self.permute()?;
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems)?;
            }
        };

        Ok(squeezed_elems)
    }
}
