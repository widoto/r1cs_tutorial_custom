import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import input from '../public/input.json';
import vk from '../public/vk.json';
import proof from '../public/proof.json';
import sig from '../public/sig.json';

describe("Verifier", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
    let mock_input = input.input;
    let mock_proof = proof.proof;
    let mock_vk = vk.vk;
    let mock_message = sig.message;
    let mock_v = sig.v;
    let mock_r = sig.r;
    let mock_s = sig.s;
    let mock_pk = sig.pk;

  async function deployVerifierFixture() {

    const [owner] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy(); 

    return { owner, verifier };
  };

  describe("Checking VroomLicenseCircuit", function () {
        
    it("isValidVroomDriver = true", async function () {
        
        const { verifier } = await loadFixture(deployVerifierFixture);
        
        const result = await verifier.verifyProof.staticCall(mock_vk,mock_proof,mock_input);
        
        expect(result).to.equal(true);
    });

    it("isSignatureValid = true", async function () {
        
      const { verifier } = await loadFixture(deployVerifierFixture);
      
      const result = await verifier.verifySignature.staticCall(mock_message, mock_v, mock_r, mock_s, mock_pk);
      
      expect(result).to.equal(true);
  });

  });
});
