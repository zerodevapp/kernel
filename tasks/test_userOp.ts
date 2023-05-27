
import { task } from "hardhat/config"
import { hexConcat, arrayify } from "ethers/lib/utils"

const STACKUP = "https://api.stackup.sh/v1/node/<STACKUP_API>"

task("test-userop", "deploy erc20 paymaster")
    .setAction(async (taskArgs, hre) => {
      const signer = (await hre.ethers.getSigners())[0];
      const addr = await signer.getAddress();
      console.log("signer address: ", addr);
      const entrypoint = await hre.ethers.getContractAt("EntryPoint", "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
      const ecdsaFactory = await hre.ethers.getContractAt("ECDSAKernelFactory", "0x6b337f4ddb17b4ba93bcde99661ab46aec1d2823");
      const account = await ecdsaFactory.getAccountAddress(addr, 0);
      const kernel = await hre.ethers.getContractAt("Kernel", account);
      console.log("maxFeePerGas : ", await hre.ethers.provider.getGasPrice());
      const userOp = {
        sender : account,
        nonce : 0,
        initCode : hexConcat([ecdsaFactory.address, ecdsaFactory.interface.encodeFunctionData("createAccount", [addr, 0])]),
        callData : kernel.interface.encodeFunctionData("execute", [addr,0,"0x",0]),
        callGasLimit : 33100,
        verificationGasLimit : 300000,
        preVerificationGas : 45100,
        maxFeePerGas: (await hre.ethers.provider.getGasPrice()).toHexString(),
        maxPriorityFeePerGas: 1000000000,
        paymasterAndData: "0x",
        signature: "0x"
      }
      const userOpHash = await entrypoint.getUserOpHash(userOp);
      const userOpHashHex = arrayify(userOpHash);
      const userOpSig = await signer.signMessage(userOpHashHex);
      console.log("userOpSig: ", userOpSig);
      userOp.signature = hexConcat(["0x00000000", userOpSig])
      if((await hre.ethers.provider.getBalance(account)).lt(hre.ethers.BigNumber.from("100000000000000000"))) {
        console.log("insufficient balance");
        await signer.sendTransaction({
          to: account,
          value: hre.ethers.BigNumber.from("100000000000000000")
        })
      }
      const stackup = new hre.ethers.providers.JsonRpcProvider(STACKUP);
      const receipt = await stackup.send("eth_sendUserOperation", [userOp, entrypoint.address]);
    })
