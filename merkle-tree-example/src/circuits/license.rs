use crate::gadgets::hash::pedersen::common::*;
use crate::gadgets::hash::pedersen::constraints::{RootVar, SimplePathVar};
use crate::{Root, SimplePath};

use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
use ark_ed_on_bls12_381::Fq as Fp;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// statement = {[20, 30], rt, current_time, h_birthday, h_exp}
// witness = {이름, 생년월일, 유효기간}

#[derive(Clone)]
pub struct VroomLicenseCircuit<Fp> {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,
    // pub leaf_birth: Fp, // 이걸 숨기고 싶은건데 왜...?
    pub leaf_exp: Fp,
    pub cur_time: Fp,

    // This is the private witness to the circuit.
    pub auth_path_exp: Option<SimplePath>,
    pub auth_path_birth: Option<SimplePath>,
    pub birth: Fp,
}

impl ConstraintSynthesizer<Fp> for VroomLicenseCircuit<Fp> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fp>) -> Result<(), SynthesisError> {
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf_exp = FpVar::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf_exp))?;
        let cur_time =
            FpVar::new_input(ark_relations::ns!(cs, "curtime_var"), || Ok(&self.cur_time))?;

        let auth_path_exp = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.auth_path_exp.as_ref().unwrap())
        })?;

        let auth_path_birth =
            SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                Ok(self.auth_path_birth.as_ref().unwrap())
            })?;
        let birth = FpVar::new_witness(ark_relations::ns!(cs, "birth_var"), || Ok(self.birth))?;

        let is_member_exp = auth_path_exp.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_exp,
        )?;

        is_member_exp.enforce_equal(&Boolean::TRUE)?;

        let is_member_birth = auth_path_birth.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &birth,
        )?;

        is_member_birth.enforce_equal(&Boolean::TRUE)?;

        // 20세 이상인가?
        let gap = cur_time - birth;
        let age20 = Fp::from(199999u64);
        let gap_std = FpVar::new_constant(cs.clone(), age20)?;

        gap.enforce_cmp(&gap_std, std::cmp::Ordering::Greater, false)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {

    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::crh::TwoToOneCRH;
    use ark_groth16::Groth16;
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    use crate::{
        circuits::{license::VroomLicenseCircuit, merkle_tree::MerkleTreeCircuit},
        gadgets::hash::pedersen::common::{LeafHash, TwoToOneHash},
        SimpleMerkleTree,
    };

    #[test]
    fn test_merkle_trees() {
        use ark_crypto_primitives::crh::CRH;
        use ark_ed_on_bls12_381::Fq as Fp;

        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        // let mut rng = ark_std::test_rng();
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[
                Fp::from(20400318u64), // exp
                Fp::from(20010319u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
            ], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item.
        let proof_exp = tree.generate_proof(0).unwrap(); // we're 0-indexing!
                                                         // This should be a proof for the membership of a leaf with value 9. Let's check that!

        let proof_birth = tree.generate_proof(1).unwrap();
        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = VroomLicenseCircuit {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf_exp: Fp::from(20400318u64),
            cur_time: Fp::from(20250219u64),

            // witness
            auth_path_exp: Some(proof_exp),
            auth_path_birth: Some(proof_birth),
            birth: Fp::from(20010319u64),
        };

        let (pk, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), rng).unwrap();

        let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();

        // let leaf_fp = BigInteger256::from(9u8);
        let leaf_exp = Fp::from(20400318u64);
        let cur_time = Fp::from(20250219u64);
        let verify_inputs = [root, leaf_exp, cur_time];

        let proofs = Groth16::<Bls12_381>::prove(&pk, circuit, rng).unwrap();

        assert!(
            Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &verify_inputs, &proofs).unwrap(),
        )
    }
}
