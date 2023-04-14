import { MerkleTree } from 'merkletreejs';
import keccak256 from 'keccak256';
import { expect } from 'chai';
import { ethers } from 'hardhat'
import { Signer, BytesLike, BigNumber } from 'ethers';
import { hexConcat, hexZeroPad } from 'ethers/lib/utils';
import { AccountFactory, AccountFactory__factory, Kernel, Kernel__factory, TestCounter, TestCounter__factory, ZeroDevSessionKeyPlugin, ZeroDevSessionKeyPlugin__factory } from '../../typechain-types';
import { EntryPoint, EntryPoint__factory } from "../../types";

async function signSessionKey(kernel: Kernel, sessionPlugin: ZeroDevSessionKeyPlugin, owner: Signer, sessionKey: Signer, merkleRoot: string): Promise<any> {
  const ownerSig = await owner._signTypedData(
    {
      name: "Kernel",
      version: "0.0.1",
      chainId: await ethers.provider.getNetwork().then(x => x.chainId),
      verifyingContract: kernel.address,
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
      plugin: sessionPlugin.address,
      validUntil: 0,
      validAfter: 0,
      data: hexConcat([
        await sessionKey.getAddress(),
        hexZeroPad(merkleRoot, 32),
      ])
    }
  );
  return ownerSig;
}

async function getSessionSig(nonce: BigNumber, kernel: Kernel, sessionKey: Signer, userOpHash: BytesLike): Promise<any> {
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

describe('SessionKey', function () {
  let sessionKey: ZeroDevSessionKeyPlugin;
  let owner: Signer;
  let entrypoint: EntryPoint;
  let accountFactory: AccountFactory;
  let kernelTemplate: Kernel;
  let kernel: Kernel;
  let testCounter: TestCounter;
  let session: Signer;
  let merkle: MerkleTree;
  beforeEach(async function () {
    [owner, session] = await ethers.getSigners();
    entrypoint = await new EntryPoint__factory(owner).deploy();
    sessionKey = await new ZeroDevSessionKeyPlugin__factory(owner).deploy();
    accountFactory = await new AccountFactory__factory(owner).deploy(entrypoint.address);
    kernelTemplate = await new Kernel__factory(owner).deploy(entrypoint.address);
    await accountFactory.createAccount(await owner.getAddress(), 0);
    kernel = Kernel__factory.connect(await accountFactory.getAccountAddress(await owner.getAddress(), 0), owner);
    await kernel.upgradeTo(kernelTemplate.address);
    testCounter = await new TestCounter__factory(owner).deploy();
  })
  it("test", async function () {
    const nonce = await entrypoint.getNonce(kernel.address, await session.getAddress());
    let op = {
      sender: kernel.address,
      nonce: nonce,
      initCode: "0x",
      callData: kernel.interface.encodeFunctionData("executeAndRevert", [
        testCounter.address,
        0,
        testCounter.interface.encodeFunctionData("increment"),
        0
      ]),
      callGasLimit: 100000,
      verificationGasLimit: 200000,
      preVerificationGas: 100000,
      maxFeePerGas: 100000,
      maxPriorityFeePerGas: 100000,
      paymasterAndData: "0x",
      signature: "0x"
    }
    const userOpHash = (await entrypoint.getUserOpHash(op));

    merkle = new MerkleTree(
      [
        hexZeroPad(testCounter.address, 20)
      ],
      keccak256,
      { sortPairs: true, hashLeaves: true }
    );
    console.log("hexZeroPad :", hexZeroPad(testCounter.address, 20));
    console.log("length :", hexZeroPad(testCounter.address, 20).length);
    const proof = merkle.getHexProof(ethers.utils.keccak256(testCounter.address));
    console.log("testCounter :", testCounter.address);
    console.log("merkle root :", merkle.getRoot().toString('hex'));
    console.log(proof);
    const ownerSig = await signSessionKey(
      kernel,
      sessionKey,
      owner,
      session,
      "0x" + merkle.getRoot().toString('hex')
    );

    await owner.sendTransaction({
      to: kernel.address,
      value: ethers.utils.parseEther("10.0")
    });

    const sessionsig = await getSessionSig(nonce, kernel, session, userOpHash);
    console.log("owner address : ", await owner.getAddress());
    console.log("owner balance before : ", await owner.getBalance());
    op.signature = hexConcat([
      hexConcat([
        sessionKey.address,
        hexZeroPad("0x00", 12), // validUntil + validAfter
        ownerSig, // signature
      ]),
      ethers.utils.defaultAbiCoder.encode([
        "bytes",
        "bytes"
      ], [
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
          ], [
            proof
          ]),
        ])
      ])]),

      await entrypoint.handleOps([op], await owner.getAddress())
    console.log("owner balance after : ", await owner.getBalance());
  })
})
