use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};
pub mod circuits;
pub mod gadgets;
use ark_ec::PairingEngine;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
// use ccgroth16::{default_pk, CCGroth16, Proof, ProvingKey, ProvingKeyIO, VerifyingKeyIO};
use gadgets::hash::pedersen::common::*;
use std::ffi::{c_char, CStr};
use std::sync::RwLock;
use std::{ffi::CString, fs, ops::Mul};

// file
#[macro_use]
extern crate lazy_static;

type E = ark_bn254::Bn254;
pub struct VerifyingKeyIO<E: PairingEngine> {
    pub vk: VerifyingKey<E>,
}

pub fn default_pk<E: PairingEngine>() -> ProvingKey<E> {
    ProvingKey::<E> {
        vk: VerifyingKey::default(),
        beta_g1: E::G1Affine::default(),
        delta_g1: E::G1Affine::default(),
        a_query: Vec::new(),
        b_g1_query: Vec::new(),
        b_g2_query: Vec::new(),
        h_query: Vec::new(),
        l_query: Vec::new(),
    }
}

// mod constraints_test;
lazy_static! {
    pub static ref PK_FILE: String = "license.pk.dat".to_string();
    pub static ref VK_FILE: String = "license.vk.dat".to_string();
    pub static ref PRF_FILE: String = "license.proof.dat".to_string();
    static ref PK: RwLock<ProvingKey<E>> = RwLock::new(default_pk());
    static ref CK: RwLock<[<E as PairingEngine>::G1Affine; 2]> =
        RwLock::new([<E as PairingEngine>::G1Affine::zero(); 2]);
}

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes: one to hash leaves, and one to hash pairs
    // of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree() {
    use ark_crypto_primitives::crh::CRH;
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
    )
    .unwrap();

    // Now, let's try to generate a membership proof for the 5th item.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &[9u8], // The claimed leaf
        )
        .unwrap();
    assert!(result);
}

// SC로 반환하는 부분 : r, rt, sigma, ek, vk, proof

pub fn hex_to_scalar<E: PairingEngine>(hex: &str) -> E::ScalarField {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(format!("{:0>64}", hex)).unwrap();

    // CHECK
    E::ScalarField::from_be_bytes_mod_order(&bytes)
}

pub fn str_from_c_str<'a>(ptr: *const c_char) -> &'a str {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let str = c_str.to_str().expect("Invalid UTF-8");
    str
}

#[no_mangle]
pub extern "C" fn get_vk_bn254(param_path: *const c_char) -> *mut c_char {
    let path = str_from_c_str(param_path);
    let vk_file = format!("{}{}", path, VK_FILE.as_str());
    let vk_io = VerifyingKeyIO::<E>::from(vk_file);
    let c_string_vk = CString::new(vk_io.to_string()).expect("CString::new failed");
    c_string_vk.into_raw()
}

#[no_mangle]
pub extern "C" fn get_proof_bn254(proof_path: *const c_char) -> *mut c_char {
    // Path prefix
    let path = str_from_c_str(proof_path);
    let prf_file = format!("{}{}", path, PRF_FILE.as_str());

    let proof = Proof::<E>::from(prf_file);
    let c_string_proof = CString::new(proof.to_string()).expect("CString::new failed");

    c_string_proof.into_raw()
}
