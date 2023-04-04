import { MerkleTree } from 'merkletreejs';
import keccak256 from 'keccak256';
import { expect } from 'chai';
import { ethers } from 'hardhat'
import { Signer, BytesLike, BigNumber } from 'ethers';
import { hexConcat, hexZeroPad } from 'ethers/lib/utils';
import { AccountFactory, AccountFactory__factory, Kernel, Kernel__factory,TestCounter,TestCounter__factory,ZeroDevSessionKeyPlugin, ZeroDevSessionKeyPlugin__factory } from '../../typechain-types';


async function signSessionKey(kernel: Kernel, sessionPlugin: ZeroDevSessionKeyPlugin, owner: Signer, sessionKey: Signer, merkleRoot: string) : Promise<any> {
  const ownerSig = await owner._signTypedData(
    {
      name : "Kernel",
      version : "0.0.1",
      chainId : await ethers.provider.getNetwork().then(x => x.chainId),
      verifyingContract : kernel.address,
    },
    {
      ValidateUserOpPlugin: [
        { name: "plugin", type: "address" },
        { name: "validUntil", type: "uint48" },
        { name: "validAfter", type: "uint48" },
        { name: "data", type: "bytes" },
      ]
    },
    {
      plugin : sessionPlugin.address,
      validUntil : 0,
      validAfter : 0,
      data : hexConcat([
        await sessionKey.getAddress(),
        hexZeroPad(merkleRoot, 32),
      ])
    }
  );
  return ownerSig;
}

async function getSessionSig(kernel: Kernel, sessionPlugin: ZeroDevSessionKeyPlugin, sessionKey: Signer, userOpHash : BytesLike) : Promise<any> {
  const nonce = await kernel.queryPlugin(sessionPlugin.address, sessionPlugin.interface.encodeFunctionData("sessionNonce", [await sessionKey.getAddress()])).catch((e) => {
    try {
      return BigNumber.from(e.message.split("QueryResult(\\\"")[1].split("\\\")")[0]);
    } catch(e: any) {
      throw Error("Failed to parse nonce : " + e.message);
    }
  });
  const sessionsig = await sessionKey._signTypedData(
    {
      name: "ZeroDevSessionKeyPlugin",
      version: "0.0.1",
      chainId: await ethers.provider.getNetwork().then(x => x.chainId),
      verifyingContract: kernel.address,
    },
    {
      Session: [
        { name: "userOpHash", type: "bytes32" },
        { name: "nonce", type: "uint256" },
      ]
    },
    {
      userOpHash: hexZeroPad(userOpHash, 32),
      nonce: nonce
    }
  );
  return sessionsig;
}

describe('SessionKey', function() {
  let sessionKey: ZeroDevSessionKeyPlugin;
  let owner: Signer;
  let entrypoint: Signer;
  let accountFactory : AccountFactory;
  let kernelTemplate : Kernel;
  let kernel : Kernel;
  let testCounter : TestCounter;
  let session : Signer;
  let merkle : MerkleTree;
  beforeEach(async function(){
    [owner, entrypoint, session] = await ethers.getSigners();
    sessionKey = await new ZeroDevSessionKeyPlugin__factory(owner).deploy();
    accountFactory = await new AccountFactory__factory(owner).deploy(await entrypoint.getAddress());
    kernelTemplate = await new Kernel__factory(owner).deploy(await entrypoint.getAddress());
    await accountFactory.createAccount(await owner.getAddress(), 0);
    kernel = Kernel__factory.connect(await accountFactory.getAccountAddress(await owner.getAddress(), 0), owner);
    await kernel.upgradeTo(kernelTemplate.address);
    testCounter = await new TestCounter__factory(owner).deploy();
  })
  it("test", async function(){
    const userOpHash = ethers.utils.randomBytes(32);
    merkle = new MerkleTree(
      [
        hexZeroPad(testCounter.address, 20),
        hexZeroPad(ethers.utils.randomBytes(20),20)
      ],
      keccak256,
      { sortPairs: true, hashLeaves: true }
    );
    const proof = merkle.getHexProof(ethers.utils.keccak256(testCounter.address));
    console.log("testCounter :",testCounter.address);
    console.log("merkle root :",merkle.getRoot().toString('hex'));
    console.log(proof);
    const ownerSig = await signSessionKey(
      kernel,
      sessionKey,
      owner,
      session,
      "0x" + merkle.getRoot().toString('hex')
    );

    const sessionsig = await getSessionSig(kernel, sessionKey, session, userOpHash);
    await kernel.connect(entrypoint).validateUserOp({
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
          ownerSig, // signature
        ]),
        ethers.utils.defaultAbiCoder.encode([
          "bytes",
          "bytes"
        ],[
          hexConcat([
            await session.getAddress(),
            hexZeroPad("0x" + merkle.getRoot().toString('hex'), 32),
          ]),
          hexConcat([
            hexZeroPad("0x14", 1),
            testCounter.address,
            hexZeroPad(sessionsig, 65),
            ethers.utils.defaultAbiCoder.encode([
              "bytes32[]"
            ],[
              proof
            ]),
          ])
        ])]),
    },userOpHash,0)
 })
})
