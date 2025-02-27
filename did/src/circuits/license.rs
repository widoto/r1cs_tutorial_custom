use crate::gadgets::hash::pedersen::common::*;
use crate::gadgets::hash::pedersen::constraints::{RootVar, SimplePathVar};
use crate::{Root, SimplePath};

use ark_bn254::Fr as Fp;
use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
use ark_crypto_primitives::CRHGadget;
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::EdwardsProjective as JubJub;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
type TestCRHGadget =
    ark_crypto_primitives::crh::pedersen::constraints::CRHGadget<JubJub, EdwardsVar, LeafWindow>;

#[derive(Clone)]
pub struct VroomLicenseCircuit<Fp> {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,     // value of merkle root
    pub exp_hash: Fp,   // leaf node of mt
    pub birth_hash: Fp, // leaf node of mt
    pub cur_time: Fp,   // criterion time

    // This is the private witness to the circuit.
    pub auth_path_exp: Option<SimplePath>,
    pub auth_path_birth: Option<SimplePath>,
    pub birth: Fp,
    pub birth_rng: <LeafHash as CRH>::Parameters, // TODO : only put rng
    pub exp: Fp,
    pub exp_rng: <LeafHash as CRH>::Parameters, // TODO : only put rng
}

impl ConstraintSynthesizer<Fp> for VroomLicenseCircuit<Fp> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fp>) -> Result<(), SynthesisError> {
        // constant
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let exp_hash =
            FpVar::new_input(
                ark_relations::ns!(cs, "exp_hash_var"),
                || Ok(&self.exp_hash),
            )?;

        let birth_hash = FpVar::new_input(ark_relations::ns!(cs, "birth_hash_var"), || {
            Ok(&self.birth_hash)
        })?;

        let cur_time =
            FpVar::new_input(ark_relations::ns!(cs, "curtime_var"), || Ok(&self.cur_time))?;

        // witness
        let auth_path_exp =
            SimplePathVar::new_witness(ark_relations::ns!(cs, "exp_path_var"), || {
                Ok(self.auth_path_exp.as_ref().unwrap())
            })?;

        let auth_path_birth =
            SimplePathVar::new_witness(ark_relations::ns!(cs, "birth_path_var"), || {
                Ok(self.auth_path_birth.as_ref().unwrap())
            })?;

        let birth = FpVar::new_witness(ark_relations::ns!(cs, "birth_var"), || Ok(self.birth))?;
        let birth_rng =
            LeafHashParamsVar::new_witness(ark_relations::ns!(cs, "birth_rng_var"), || {
                Ok(&self.birth_rng)
            })?;

        let exp = FpVar::new_witness(ark_relations::ns!(cs, "exp_var"), || Ok(self.exp))?;
        let exp_rng =
            LeafHashParamsVar::new_witness(ark_relations::ns!(cs, "exp_rng_var"), || {
                Ok(&self.birth_rng)
            })?;

        // check hash of birth
        let birth_bytes = birth.to_bytes()?;
        let predicted_birth_hash = TestCRHGadget::evaluate(&birth_rng, &birth_bytes).unwrap();
        birth_hash.enforce_equal(&predicted_birth_hash.x)?;

        // check hash of exp
        let exp_bytes = exp.to_bytes()?;
        let predicted_exp_hash = TestCRHGadget::evaluate(&exp_rng, &exp_bytes).unwrap();
        exp_hash.enforce_equal(&predicted_exp_hash.x)?;

        // check membership of expiration
        let is_member_exp = auth_path_exp.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &exp_hash,
        )?;

        is_member_exp.enforce_equal(&Boolean::TRUE)?;

        // check membership of birth
        let is_member_birth = auth_path_birth.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &birth_hash,
        )?;

        is_member_birth.enforce_equal(&Boolean::TRUE)?;

        // check expiration > current
        exp.enforce_cmp(&cur_time, std::cmp::Ordering::Greater, false)?;

        // 20 < age < 30
        let age_gap = cur_time - birth;
        let criterion_low = FpVar::Constant(Fp::from(19u64));
        let criterion_high = FpVar::Constant(Fp::from(30u64));
        age_gap.enforce_cmp(&criterion_low, std::cmp::Ordering::Greater, false)?;
        criterion_high.enforce_cmp(&age_gap, std::cmp::Ordering::Greater, false)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {

    use ark_crypto_primitives::crh::TwoToOneCRH;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };
    use serde_json::json;

    use crate::{
        circuits::license::VroomLicenseCircuit,
        gadgets::hash::pedersen::common::{LeafHash, TwoToOneHash},
        SimpleMerkleTree,
    };
    use num_bigint::BigUint;
    use sha3::{Digest, Keccak256};
    use std::fs;

    #[test]
    fn test_did() {
        use ark_bn254::Fr as Fp;
        use ark_crypto_primitives::crh::CRH;
        use secp256k1::{Message, Secp256k1, SecretKey};

        // birth hash
        let birth: ark_ff::Fp256<ark_bn254::FrParameters> = Fp::from(2001u64);

        let rng_b = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let birth_rng: ark_crypto_primitives::crh::pedersen::Parameters<
            ark_ec::twisted_edwards_extended::GroupProjective<ark_ed_on_bn254::EdwardsParameters>,
        > = <LeafHash as CRH>::setup(rng_b).unwrap();

        let birth_big = BigUint::from_bytes_le(&birth.into_repr().to_bytes_le());
        let birth_bytes = birth_big.to_bytes_le();
        let birth_hash = <LeafHash as CRH>::evaluate(&birth_rng, &birth_bytes).unwrap();

        // expire hash
        let exp = Fp::from(2040u64);

        let rng_e = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let exp_rng: ark_crypto_primitives::crh::pedersen::Parameters<
            ark_ec::twisted_edwards_extended::GroupProjective<ark_ed_on_bn254::EdwardsParameters>,
        > = <LeafHash as CRH>::setup(rng_e).unwrap();

        let exp_big = BigUint::from_bytes_le(&exp.into_repr().to_bytes_le());
        let exp_bytes = exp_big.to_bytes_le();
        let exp_hash = <LeafHash as CRH>::evaluate(&exp_rng, &exp_bytes).unwrap();

        // merkle tree
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let leaf_crh_params = <LeafHash as CRH>::setup(rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(rng).unwrap();

        let tree = SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &[
                birth_hash,
                exp_hash,
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
            ],
        )
        .unwrap();

        let proof_birth = tree.generate_proof(0).unwrap();
        let proof_exp = tree.generate_proof(1).unwrap();
        let root = tree.root();
        // cur year
        let cur_time = Fp::from(2025u64);

        let circuit = VroomLicenseCircuit {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            exp_hash,
            birth_hash,
            cur_time,

            // witness
            auth_path_exp: Some(proof_exp),
            auth_path_birth: Some(proof_birth),
            birth,
            birth_rng,
            exp,
            exp_rng,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit.clone(), rng).unwrap();

        let pvk = Groth16::<ark_bn254::Bn254>::process_vk(&vk).unwrap();

        let verify_inputs = [root, exp_hash, birth_hash, cur_time];

        let proofs = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit.clone(), rng).unwrap();

        let proof_json = json!({
            "proof": [
                BigUint::from_bytes_be(&proofs.a.x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.a.y.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.b.x.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.b.x.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.b.y.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.b.y.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.c.x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&proofs.c.y.into_repr().to_bytes_be()).to_str_radix(10)
            ]
        });

        // println!("proof : {:?}", proof_json);

        fs::write("../contract/public/proof.json", proof_json.to_string())
            .expect("Failed to save proof");

        let beta_g2 = -vk.beta_g2;
        let delta_g2 = -vk.delta_g2;
        let gamma_g2 = -vk.gamma_g2;

        let vk_json = json!({
            "vk": [
                BigUint::from_bytes_be(&vk.alpha_g1.x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.alpha_g1.y.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&beta_g2.x.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&beta_g2.x.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&beta_g2.y.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&beta_g2.y.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&delta_g2.x.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&delta_g2.x.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&delta_g2.y.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&delta_g2.y.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&gamma_g2.x.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&gamma_g2.x.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&gamma_g2.y.c1.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&gamma_g2.y.c0.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[0].x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[0].y.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[1].x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[1].y.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[2].x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[2].y.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[3].x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[3].y.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[4].x.into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&vk.gamma_abc_g1[4].y.into_repr().to_bytes_be()).to_str_radix(10)
            ]
        });

        //print!("vk : {:?}", vk_json);
        /*let mut gamma_abc_g1 = String::new();
        for g in &vk.gamma_abc_g1 {
            let (x, y) = (g.x, g.y);
            println!(
                "{:?}, {:?} : input count",
                x.into_repr().to_string(),
                y.into_repr().to_string()
            );
        }*/

        fs::write("../contract/public/vk.json", vk_json.to_string()).expect("Failed to save vk");

        let input_json = json!({
            "input": [
                BigUint::from_bytes_be(&verify_inputs[0].into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&verify_inputs[1].into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&verify_inputs[2].into_repr().to_bytes_be()).to_str_radix(10),
                BigUint::from_bytes_be(&verify_inputs[3].into_repr().to_bytes_be()).to_str_radix(10),
            ]
        });

        //println!("input : {:?}", input_json);
        fs::write("../contract/public/input.json", input_json.to_string())
            .expect("Failed to save vk");

        assert!(Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(
            &pvk,
            &verify_inputs,
            &proofs
        )
        .unwrap(),);

        // get number of constraints
        let cs = ConstraintSystem::<Fp>::new_ref();

        circuit.generate_constraints(cs.clone()).unwrap();
        let num_constraints = cs.num_constraints();
        println!("Number of constraints: {:?}", num_constraints);

        // signature
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let message = BigUint::from_bytes_be(&root.into_repr().to_bytes_be()).to_str_radix(10);

        // add Ethereum Signed Message prefix
        let eth_prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let eth_message = [eth_prefix.as_bytes(), message.as_bytes()].concat();
        let message_hash = Keccak256::digest(&eth_message);

        let m = Message::from_slice(&message_hash).expect("32-byte message hash");
        let (rec_id, sig_bytes) = secp
            .sign_ecdsa_recoverable(&m, &secret_key)
            .serialize_compact();

        let v = rec_id.to_i32() as u8 + 27;
        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];

        let pubkey_bytes = public_key.serialize_uncompressed();
        let pubkey_hash = Keccak256::digest(&pubkey_bytes[1..]);
        let eth_address = &pubkey_hash[12..];

        let sig_json = json!({
            "message": message,
            "v": v,
            "r" : "0x".to_owned() + &hex::encode(r),
            "s" : "0x".to_owned() + &hex::encode(s),
            "pk" : "0x".to_owned() + &hex::encode(eth_address)
        });

        //println!("input : {:?}", input_json);
        fs::write("../contract/public/sig.json", sig_json.to_string()).expect("Failed to save sig");

        println!("Message: {}", message);
        println!("Ethereum Address: 0x{}", hex::encode(eth_address));
        println!("v: {}, r: 0x{}, s: 0x{}", v, hex::encode(r), hex::encode(s));
    }
}
