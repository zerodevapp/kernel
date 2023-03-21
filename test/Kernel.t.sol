// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "account-abstraction/core/EntryPoint.sol";

contract KernelTest is Test {
    EntryPoint entryPoint;
    function setUp() public {
        entryPoint = new EntryPoint();
    }

    function testKernel() public {
        assertTrue(true);
    }
}