import { ethers } from "hardhat";

async function main() {
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);

    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();

    console.log("verifier address:", await verifier.getAddress());
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
