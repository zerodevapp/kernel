
import { task } from "hardhat/config"
import { hexConcat, arrayify, hexZeroPad } from "ethers/lib/utils"

const STACKUP = "https://api.stackup.sh/v1/node/65bdd496f420d5610b504691af2787cda9a580cd2be7d3fb64a78fc17bc65c42"

task("test-userop-initcode", "deploy erc20 paymaster")
    .setAction(async (taskArgs, hre) => {
      const signer = (await hre.ethers.getSigners())[0];
      const addr = await signer.getAddress();
      console.log("signer address: ", addr);
      const entrypoint = await hre.ethers.getContractAt("EntryPoint", "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
      const ecdsaFactory = await hre.ethers.getContractAt("ECDSAKernelFactory", "0x08e627ca6a0593c807091726a7fbb2887a1cb556");
      const account = await ecdsaFactory.getAccountAddress(addr, 3);
      const kernel = await hre.ethers.getContractAt("Kernel", account);
      console.log("maxFeePerGas : ", await hre.ethers.provider.getGasPrice());
      const userOp = {
        sender : account,
        nonce : 0,
        initCode : hexConcat([ecdsaFactory.address, ecdsaFactory.interface.encodeFunctionData("createAccount", [addr, 3])]),
        callData : kernel.interface.encodeFunctionData("execute", [addr,0,"0x",0]),
        callGasLimit : 100000,
        verificationGasLimit : 300000,
        preVerificationGas : 300000,
        maxFeePerGas: (await hre.ethers.provider.getGasPrice()).toHexString(),
        maxPriorityFeePerGas: 1000000000,
        paymasterAndData: "0x",
        signature: "0x"
      }
      if((await hre.ethers.provider.getBalance(account)).lt(hre.ethers.BigNumber.from("100000000000000000"))) {
        console.log("insufficient balance");
        await signer.sendTransaction({
          to: account,
          value: hre.ethers.BigNumber.from("100000000000000000")
        })
      }

      const stackup = new hre.ethers.providers.JsonRpcProvider(STACKUP);
      userOp.signature = hexConcat(["0x00000000", hexZeroPad("0xb1", 65)])
      const gas = await stackup.send("eth_estimateUserOperationGas", [userOp, entrypoint.address]);
      console.log("gas: ", gas);
      userOp.callGasLimit = gas.callGasLimit;
      userOp.verificationGasLimit = gas.verificationGas;
      userOp.preVerificationGas = gas.preVerificationGas;
      const userOpHash = await entrypoint.getUserOpHash(userOp);
      const userOpHashHex = arrayify(userOpHash);
      const userOpSig = await signer.signMessage(userOpHashHex);

      console.log("userOpSig: ", userOpSig);
      userOp.signature = hexConcat(["0x00000000", userOpSig])
      const receipt = await stackup.send("eth_sendUserOperation", [userOp, entrypoint.address]);
    })

task("test-userop", "test userop")
    .setAction(async (taskArgs, hre) => {
      const kernel_id = 3;
      const signer = (await hre.ethers.getSigners())[0];
      const addr = await signer.getAddress();
      console.log("signer address: ", addr);
      const entrypoint = await hre.ethers.getContractAt("EntryPoint", "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
      const ecdsaFactory = await hre.ethers.getContractAt("ECDSAKernelFactory", "0x08e627ca6a0593c807091726a7fbb2887a1cb556");
      const account = await ecdsaFactory.getAccountAddress(addr, kernel_id);
      //await ecdsaFactory.createAccount(addr, kernel_id);
      const kernel = await hre.ethers.getContractAt("Kernel", account);
      console.log("maxFeePerGas : ", await hre.ethers.provider.getGasPrice());
      const userOp = {
        sender : account,
        nonce : (await entrypoint.getNonce(account,0)).toHexString(),
        initCode : "0x",
        callData : kernel.interface.encodeFunctionData("execute", [addr,0,"0x",0]),
        callGasLimit : 100000,
        verificationGasLimit : 300000,
        preVerificationGas : 45100,
        maxFeePerGas: (await hre.ethers.provider.getGasPrice()).toHexString(),
        maxPriorityFeePerGas: 1000000000,
        paymasterAndData: "0x",
        signature: "0x"
      }
      if((await hre.ethers.provider.getBalance(account)).lt(hre.ethers.BigNumber.from("100000000000000000"))) {
        console.log("insufficient balance");
        await signer.sendTransaction({
          to: account,
          value: hre.ethers.BigNumber.from("100000000000000000")
        })
      }

      const stackup = new hre.ethers.providers.JsonRpcProvider(STACKUP);
      userOp.signature = hexConcat(["0x00000000", hexZeroPad("0x8f51af942b92e95ec77b4ae8b4197ca94373be26205746c506997587d0fd5efe6f5ea33ea7fcf09c9cd38216837c4739a8283d6f97e9977aa1f102fee5d0516b1b", 65)])
      const gas = await stackup.send("eth_estimateUserOperationGas", [userOp, entrypoint.address]);
      console.log("gas: ", gas);
      userOp.callGasLimit = gas.callGasLimit;
      userOp.verificationGasLimit = gas.verificationGas;
      userOp.preVerificationGas = gas.preVerificationGas;
      const userOpHash = await entrypoint.getUserOpHash(userOp);
      const userOpHashHex = arrayify(userOpHash);
      const userOpSig = await signer.signMessage(userOpHashHex);

      console.log("userOpSig: ", userOpSig);
      userOp.signature = hexConcat(["0x00000000", userOpSig])
      const receipt = await stackup.send("eth_sendUserOperation", [userOp, entrypoint.address]);
    })

