// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {AccountFactory} from "src/factory/AccountFactory.sol";
import {MinimalAccount} from "src/factory/MinimalAccount.sol";
import "forge-std/Test.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {Operation} from "src/utils/Exec.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

using ECDSA for bytes32;

contract AccountFactoryTest is Test {
    AccountFactory accountFactory;
    EntryPoint entryPoint;
    TestCounter testCounter;

    address user1;
    uint256 user1PrivKey;
    address user2;
    address payable bundler;

    function setUp() public {
        entryPoint = new EntryPoint();
        accountFactory = new AccountFactory(entryPoint);
        (user1, user1PrivKey) = makeAddrAndKey("user1");
        user2 = makeAddr("user2");
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

    function testAccountFactory(uint256 i) public {
        address payable account = payable(address(accountFactory.createAccount(user1, i)));
        assertEq(account, address(accountFactory.getAccountAddress(user1, i)));
        assertEq(account.code.length > 0, true);
        assertEq(MinimalAccount(account).getOwner(), user1);
    }

    function testCall() public {
        address payable account = payable(accountFactory.getAccountAddress(user1, 0));
        entryPoint.depositTo{value: 1000000000000000000}(account);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: account,
            nonce: 0,
            initCode: abi.encodePacked(accountFactory, abi.encodeCall(AccountFactory.createAccount, (user1, 0))),
            callData: abi.encodeCall(
                MinimalAccount.executeAndRevert,
                (address(testCounter), 0, abi.encodeCall(TestCounter.count, ()), Operation.Call)
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
