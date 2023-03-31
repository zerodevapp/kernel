import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-foundry";
import "@nomiclabs/hardhat-ethers";
import "hardhat-deploy";
import '@typechain/hardhat'

const config: HardhatUserConfig = {
  solidity: "0.8.18",
};

export default config;
