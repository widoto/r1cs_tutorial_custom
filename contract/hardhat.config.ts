import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.28",
  networks: {
    hardhat: {
        initialBaseFeePerGas: 0,
    },
    localhost: {  // 로컬 테스트 네트워크
      url: "http://127.0.0.1:8545"
  }
},
};

export default config;
