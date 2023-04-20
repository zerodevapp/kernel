import * as dotenv from 'dotenv'
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-foundry";
import "@nomiclabs/hardhat-ethers";
import "hardhat-deploy";
import '@typechain/hardhat'
dotenv.config()


function getAccounts(): string[] | { mnemonic: string } {
  const accs = []
  if (process.env.DEPLOYER_PRIVATE_KEY !== undefined) {
    accs.push(process.env.DEPLOYER_PRIVATE_KEY)
  }
  if (process.env.PAYMASTER_OWNER_PRIVATE_KEY !== undefined) {
    accs.push(process.env.PAYMASTER_OWNER_PRIVATE_KEY)
  }
  return accs
}

const config: HardhatUserConfig = {
  solidity: "0.8.18",
  networks: {
    mumbai: {
      url: `https://polygon-mumbai.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    polygon: {
      url: `https://polygon-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    goerli: {
      url: `https://goerli.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    ethereum: {
      url: `https://mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    avalanche: {
      url: `https://avalanche-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    fuji: {
      url: `https://avalanche-fuji.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    arbitrum: {
      url: `https://arbitrum-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
  }
};

export default config;