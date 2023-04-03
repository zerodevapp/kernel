"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const merkletreejs_1 = require("merkletreejs");
const keccak256_1 = __importDefault(require("keccak256"));
const hardhat_1 = require("hardhat");
const ethers_1 = require("ethers");
const utils_1 = require("ethers/lib/utils");
const typechain_types_1 = require("../../typechain-types");
async function signSessionKey(kernel, sessionPlugin, owner, sessionKey, merkleRoot) {
    const ownerSig = await owner._signTypedData({
        name: "Kernel",
        version: "0.0.1",
        chainId: await hardhat_1.ethers.provider.getNetwork().then(x => x.chainId),
        verifyingContract: kernel.address,
    }, {
        ValidateUserOpPlugin: [
            { name: "plugin", type: "address" },
            { name: "validUntil", type: "uint48" },
            { name: "validAfter", type: "uint48" },
            { name: "data", type: "bytes" },
        ]
    }, {
        plugin: sessionPlugin.address,
        validUntil: 0,
        validAfter: 0,
        data: (0, utils_1.hexConcat)([
            await sessionKey.getAddress(),
            (0, utils_1.hexZeroPad)(merkleRoot, 32),
        ])
    });
    return ownerSig;
}
async function getSessionSig(kernel, sessionPlugin, sessionKey, userOpHash) {
    const nonce = await kernel.queryPlugin(sessionPlugin.address, sessionPlugin.interface.encodeFunctionData("sessionNonce", [await sessionKey.getAddress()])).catch((e) => {
        try {
            return ethers_1.BigNumber.from(e.message.split("QueryResult(\\\"")[1].split("\\\")")[0]);
        }
        catch (e) {
            throw Error("Failed to parse nonce : " + e.message);
        }
    });
    const sessionsig = await sessionKey._signTypedData({
        name: "ZeroDevSessionKeyPlugin",
        version: "0.0.1",
        chainId: await hardhat_1.ethers.provider.getNetwork().then(x => x.chainId),
        verifyingContract: kernel.address,
    }, {
        Session: [
            { name: "userOpHash", type: "bytes32" },
            { name: "nonce", type: "uint256" },
        ]
    }, {
        userOpHash: (0, utils_1.hexZeroPad)(userOpHash, 32),
        nonce: nonce
    });
    return sessionsig;
}
describe('SessionKey', function () {
    let sessionKey;
    let owner;
    let entrypoint;
    let accountFactory;
    let kernelTemplate;
    let kernel;
    let testCounter;
    let session;
    let merkle;
    beforeEach(async function () {
        [owner, entrypoint, session] = await hardhat_1.ethers.getSigners();
        sessionKey = await new typechain_types_1.ZeroDevSessionKeyPlugin__factory(owner).deploy();
        accountFactory = await new typechain_types_1.AccountFactory__factory(owner).deploy(await entrypoint.getAddress());
        kernelTemplate = await new typechain_types_1.Kernel__factory(owner).deploy(await entrypoint.getAddress());
        await accountFactory.createAccount(await owner.getAddress(), 0);
        kernel = typechain_types_1.Kernel__factory.connect(await accountFactory.getAccountAddress(await owner.getAddress(), 0), owner);
        await kernel.upgradeTo(kernelTemplate.address);
        testCounter = await new typechain_types_1.TestCounter__factory(owner).deploy();
    });
    it("test", async function () {
        const userOpHash = hardhat_1.ethers.utils.randomBytes(32);
        merkle = new merkletreejs_1.MerkleTree([
            (0, utils_1.hexConcat)([
                (0, utils_1.hexZeroPad)(testCounter.address, 20),
                (0, utils_1.hexZeroPad)("0x00", 12)
            ]),
            hardhat_1.ethers.utils.randomBytes(32)
        ], keccak256_1.default, { sortPairs: true });
        const proof = merkle.getHexProof((0, utils_1.hexConcat)([
            (0, utils_1.hexZeroPad)(testCounter.address, 20),
            (0, utils_1.hexZeroPad)("0x00", 12)
        ]));
        merkle.getHexProof((0, utils_1.hexConcat)([hardhat_1.ethers.utils.randomBytes(32)]));
        console.log("testCounter :", testCounter.address);
        console.log("merkle root :", merkle.getRoot().toString('hex'));
        console.log(proof);
        const ownerSig = await signSessionKey(kernel, sessionKey, owner, session, "0x" + merkle.getRoot().toString('hex'));
        const sessionsig = await getSessionSig(kernel, sessionKey, session, userOpHash);
        await kernel.connect(entrypoint).validateUserOp({
            sender: hardhat_1.ethers.constants.AddressZero,
            nonce: 0,
            initCode: "0x",
            callData: kernel.interface.encodeFunctionData("executeAndRevert", [
                testCounter.address,
                0,
                testCounter.interface.encodeFunctionData("increment"),
                0
            ]),
            callGasLimit: 100000,
            verificationGasLimit: 100000,
            preVerificationGas: 100000,
            maxFeePerGas: 100000,
            maxPriorityFeePerGas: 100000,
            paymasterAndData: "0x",
            signature: (0, utils_1.hexConcat)([
                (0, utils_1.hexConcat)([
                    sessionKey.address,
                    (0, utils_1.hexZeroPad)("0x00", 12),
                    ownerSig, // signature
                ]),
                hardhat_1.ethers.utils.defaultAbiCoder.encode([
                    "bytes",
                    "bytes"
                ], [
                    (0, utils_1.hexConcat)([
                        await session.getAddress(),
                        (0, utils_1.hexZeroPad)("0x" + merkle.getRoot().toString('hex'), 32),
                    ]),
                    (0, utils_1.hexConcat)([
                        (0, utils_1.hexZeroPad)("0x14", 1),
                        testCounter.address,
                        (0, utils_1.hexZeroPad)(sessionsig, 65),
                        hardhat_1.ethers.utils.defaultAbiCoder.encode([
                            "bytes32[]"
                        ], [
                            proof
                        ]),
                    ])
                ])
            ]),
        }, userOpHash, 0);
    });
});
