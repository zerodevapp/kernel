// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "account-abstraction/core/EntryPoint.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {Kernel, KernelStorage} from "src/Kernel.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {SimpleAccountFactory, SimpleAccount} from "account-abstraction/samples/SimpleAccountFactory.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";

using ECDSA for bytes32;

contract KernelTest is Test {
    EntryPoint entryPoint;
    KernelFactory accountFactory;
    Kernel kernelTemplate;
    TestCounter testCounter;

    address payable bundler;
    address user1;
    uint256 user1PrivKey;

    function setUp() public {
        entryPoint = new EntryPoint();
        accountFactory = new KernelFactory(entryPoint);
        (user1, user1PrivKey) = makeAddrAndKey("user1");
        kernelTemplate = new Kernel(entryPoint);
        bundler = payable(makeAddr("bundler"));
        testCounter = new TestCounter();
    }

    function signUserOp(UserOperation memory op, address addr, uint256 key)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash.toEthSignedMessageHash());
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), v, r, s));
        signature = abi.encodePacked(r, s, v);
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), signature));
    }

    function testDeploySampleAccount() public {
        SimpleAccountFactory simpleAccountFactory = new SimpleAccountFactory(entryPoint);
        address payable account = payable(simpleAccountFactory.getAddress(user1, 0));
        entryPoint.depositTo{value: 1000000000000000000}(account);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: account,
            nonce: 0,
            initCode: abi.encodePacked(simpleAccountFactory, abi.encodeCall(SimpleAccountFactory.createAccount, (user1, 0))),
            callData: abi.encodeCall(
                SimpleAccount.execute, (address(testCounter), 0, abi.encodeCall(TestCounter.count, ()))
                ),
            callGasLimit: 100000,
            verificationGasLimit: 200000,
            preVerificationGas: 200000,
            maxFeePerGas: 100000,
            maxPriorityFeePerGas: 100000,
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);
        entryPoint.handleOps(ops, bundler);
        ops[0] = UserOperation({
            sender: account,
            nonce: 1,
            initCode: hex"",
            callData: abi.encodeCall(
                SimpleAccount.execute, (address(testCounter), 0, abi.encodeCall(TestCounter.count, ()))
                ),
            callGasLimit: 100000,
            verificationGasLimit: 200000,
            preVerificationGas: 200000,
            maxFeePerGas: 100000,
            maxPriorityFeePerGas: 100000,
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);
        entryPoint.handleOps(ops, bundler);
        ops[0] = UserOperation({
            sender: account,
            nonce: 2,
            initCode: hex"",
            callData: abi.encodeCall(
                SimpleAccount.execute, (address(testCounter), 0, abi.encodeCall(TestCounter.count, ()))
                ),
            callGasLimit: 100000,
            verificationGasLimit: 200000,
            preVerificationGas: 200000,
            maxFeePerGas: 100000,
            maxPriorityFeePerGas: 100000,
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);
        entryPoint.handleOps(ops, bundler);
    }
}
