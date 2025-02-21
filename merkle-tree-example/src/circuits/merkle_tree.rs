use crate::gadgets::hash::pedersen::common::*;
use crate::gadgets::hash::pedersen::constraints::{RootVar, SimplePathVar};
use crate::{Root, SimplePath};

use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
// use ark_ed_on_bls12_381::Fq as Fp;
use ark_bn254::Fr as Fp;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct MerkleTreeCircuit {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,
    pub leaf: Fp,

    // This is the private witness to the circuit.
    pub authentication_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ark_bn254::Fr> for MerkleTreeCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ark_bn254::Fr>,
    ) -> Result<(), SynthesisError> {
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf = FpVar::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.authentication_path.as_ref().unwrap())
        })?;

        //let leaf_bytes = vec![leaf; 1];

        // Now, we have to check membership. How do we do that?
        // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

        // TODO: FILL IN THE BLANK!
        // verify_membership이 가지는 leaf 타입의 경우 ToBytesGadget인데, 이거를 FieldVar는 구현을 하고 있어서 FpVar로 바꿔서 받아왔다.
        let is_member =
            path.verify_membership(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)?;
        // let is_member = XYZ
        //
        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {

    use ark_crypto_primitives::crh::TwoToOneCRH;
    use ark_groth16::Groth16;
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    use crate::{
        circuits::merkle_tree::MerkleTreeCircuit,
        gadgets::hash::pedersen::common::{LeafHash, TwoToOneHash},
        SimpleMerkleTree,
    };

    #[test]
    fn test_merkle_trees() {
        use ark_crypto_primitives::crh::CRH;
        // use ark_ed_on_bls12_381::Fq as Fp;
        use ark_bn254::Fr as Fp;

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
                Fp::from(1u8),
                Fp::from(2u8),
                Fp::from(3u8),
                Fp::from(10u8),
                Fp::from(9u8),
                Fp::from(17u8),
                Fp::from(70u8),
                Fp::from(45u8),
            ], // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                     // This should be a proof for the membership of a leaf with value 9. Let's check that!

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeCircuit {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf: Fp::from(9u8),

            // witness
            authentication_path: Some(proof),
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit.clone(), rng).unwrap();

        let pvk = Groth16::<ark_bn254::Bn254>::process_vk(&vk).unwrap();

        // let leaf_fp = BigInteger256::from(9u8);
        let leaf_fp = Fp::from(9u8);
        let verify_inputs = [root, leaf_fp];

        let proofs = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, rng).unwrap();

        assert!(Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(
            &pvk,
            &verify_inputs,
            &proofs
        )
        .unwrap(),)
    }
}
