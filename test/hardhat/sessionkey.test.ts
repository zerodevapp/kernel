import { MerkleTree } from 'merkletreejs';
import keccak256 from 'keccak256';
import { expect } from 'chai';
import { ethers } from 'hardhat'
import { Signer } from 'ethers';
import { hexConcat, hexZeroPad } from 'ethers/lib/utils';
import { Kernel, Kernel__factory,TestCounter,TestCounter__factory,ZeroDevSessionKeyPlugin, ZeroDevSessionKeyPlugin__factory } from '../../typechain-types';

describe('SessionKey', function() {
  let sessionKey: ZeroDevSessionKeyPlugin;
  let owner: Signer;
  let entrypoint: Signer;
  let kernel : Kernel;
  let testCounter : TestCounter;
  let session : Signer;
  beforeEach(async function(){
    [owner, entrypoint, session] = await ethers.getSigners();
    sessionKey = await new ZeroDevSessionKeyPlugin__factory(owner).deploy();
    kernel = await new Kernel__factory(owner).deploy(await entrypoint.getAddress());
    kernel.initialize(await owner.getAddress());
    testCounter = await new TestCounter__factory(owner).deploy();
  })
  it("test", async function(){
    const userOpHash = ethers.utils.randomBytes(32);
    const nonce = 0;
    const sig = await session._signTypedData(
      {
        name: "ZeroDevSessionKeyPlugin",
        version: "1",
        chainId: await ethers.provider.getNetwork().then(x => x.chainId),
        verifyingContract: kernel.address,
      },
      {
        SessionKeyPluginData: [
          { name: "userOpHash", type: "bytes32" },
          { name: "nonce", type: "uint256" },
        ]
      },
      {
        userOpHash: userOpHash,
        nonce: nonce
      }
    );
    console.log(sig);
    console.log(sig.length);
    await kernel.validateUserOp({
      sender : ethers.constants.AddressZero,
      nonce : 0,
      initCode : "0x",
      callData : kernel.interface.encodeFunctionData("executeAndRevert",[
        testCounter.address,
        0,
        testCounter.interface.encodeFunctionData("increment"),
        0
      ]),
      callGasLimit : 100000,
      verificationGasLimit : 100000,
      preVerificationGas : 100000,
      maxFeePerGas : 100000,
      maxPriorityFeePerGas : 100000,
      paymasterAndData: "0x",
      signature : 
      hexConcat([
        hexConcat([
          sessionKey.address,
          hexZeroPad("0x00", 12), // validUntil + validAfter
        ]),
        ethers.utils.defaultAbiCoder.encode([
          "bytes",
          "bytes"
        ],[
          hexConcat([
            await session.getAddress(),
            hexZeroPad(testCounter.address, 20),
            hexZeroPad("0x00", 12),
          ]),
          hexConcat([
            hexZeroPad("0x14", 1),
            testCounter.address,
            hexZeroPad(sig, 65),
            ethers.utils.defaultAbiCoder.encode([
              "bytes32[]"
            ],[
              []
            ]),
          ])
        ])]),
    },userOpHash,0)
  })
})
