// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {AccountFactory} from "src/factory/AccountFactory.sol";
import {MinimalAccount} from "src/factory/MinimalAccount.sol";
import "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";

contract AccountFactoryTest is Test {
    AccountFactory accountFactory;
    EntryPoint entryPoint;

    address user1;
    address user2;
    function setUp() public {
        entryPoint = new EntryPoint();
        accountFactory = new AccountFactory(entryPoint);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
    }

    function testAccountFactory(uint256 i) public {
        address account = accountFactory.createAccount(user1, i);
        assertEq(account, accountFactory.getAccountAddress(user1, i));
        assertEq(account.code.length > 0, true);
        assertEq(MinimalAccount(account).getOwner(), user1);
    }
}