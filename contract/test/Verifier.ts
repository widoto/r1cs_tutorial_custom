import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import input from '../public/input.json';
import vk from '../public/vk.json';
import proof from '../public/proof.json';

describe("Verifier", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
    let mock_input = input.input;
    let mock_proof = proof.proof;
    let mock_vk = vk.vk;

  async function deployVerifierFixture() {

    const [owner] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy(); 

    return { owner, verifier };
  };

  describe("Checking VroomLicenseCircuit", function () {
        
    it("isUpper20YearsOld = true", async function () {
        
        const { verifier } = await loadFixture(deployVerifierFixture);
        
        const result = await verifier.verifyProof.staticCall(mock_vk,mock_proof,mock_input);
        
        expect(result).to.equal(true);
    });

  });
});
