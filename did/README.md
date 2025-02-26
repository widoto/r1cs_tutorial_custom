<h1 align="center">DID study</h1>

Verify Groth16 proof about did circuit and ECDSA signature on smart contract.

## How to run

1. Run test code to generate json files about proof, signature and so on.  
   (There already exist json files in folder contract/public, so we can skip this step.)
   `     cargo test test_did -- --nocapture
    `
2. go to contract folder, try running some of the following tasks to test Verifier.ts:
   ```
   npm install --save-dev hardhat
   npx hardhat node
   npx hardhat test
   ```
