import { HardhatRuntimeEnvironment } from 'hardhat/types'
import { DeployFunction } from 'hardhat-deploy/types'

// 0.6
const entrypoint = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";

const deployKernel: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, ethers } = hre;
  const { deploy } = deployments;
  const [deployer] = await ethers.getSigners();
  console.log("Deployer address: ", await deployer.getAddress());
  const deployerAddress = await deployer.getAddress();

  const KernelFactory = await ethers.getContractFactory("KernelFactory");

  // Create a contract instance without deploying
  const contractInstance = KernelFactory.getDeployTransaction(entrypoint);

  // Estimate gas limit for the deployment transaction
  const gasEstimate = await deployer.estimateGas(contractInstance);


  // Retrieve the current gas price from the provider
  const gasPrice = await deployer.provider!.getGasPrice();

  console.log("Gas limit for deployment:", gasEstimate.toString());
  console.log("Current gas price:", gasPrice.toString());


  await deploy('KernelFactory', {
    from: deployerAddress,
    args: [entrypoint],
    log: true,
    deterministicDeployment: true,
  });

  await deploy('ZeroDevSessionKeyPlugin', {
    from: deployerAddress,
    log: true,
    deterministicDeployment: true,
  });
}

export default deployKernel
deployKernel.tags = ['ZeroDev']