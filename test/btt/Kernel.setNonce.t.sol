// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Unauthorized, InvalidNonce} from "src/types/Error.sol";

/// @title Kernel.setNonce BTT Tests
/// @notice Tests for setNonce following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.setNonce.tree
abstract contract Kernel_setNonce is BTTModifiers {
    /*//////////////////////////////////////////////////////////////
                        UNAUTHORIZED CALLER TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallerIsNotEntryPointSetNonce() {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        _;
    }

    function test_WhenCallerIsNotEntryPointSetNonce() external whenCallerIsNotEntryPointSetNonce {
        vm.expectRevert(Unauthorized.selector);
        kernel.setNonce(0, 1);
    }

    /*//////////////////////////////////////////////////////////////
                        AUTHORIZED CALLER TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallerIsEntryPointOrSelfSetNonce() {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    function test_GivenSeqIsGreaterThanCurrentSequenceForTheNonceKey() external whenCallerIsEntryPointOrSelfSetNonce {
        uint192 nonceKey = 123;
        uint64 newSeq = 100;

        // Set nonce to a higher value
        kernel.setNonce(nonceKey, newSeq);

        // Now we can verify by trying to set a lower value which should revert
        vm.expectRevert(InvalidNonce.selector);
        kernel.setNonce(nonceKey, newSeq - 1);
    }

    function test_GivenSeqIsEqualToCurrentSequence() external whenCallerIsEntryPointOrSelfSetNonce {
        uint192 nonceKey = 456;
        uint64 seq = 50;

        // Set initial nonce
        kernel.setNonce(nonceKey, seq);

        // Trying to set the same sequence should revert (seq must be > current)
        vm.expectRevert(InvalidNonce.selector);
        kernel.setNonce(nonceKey, seq);
    }

    function test_GivenSeqIsLessThanCurrentSequence() external whenCallerIsEntryPointOrSelfSetNonce {
        uint192 nonceKey = 789;

        // Set nonce to a value
        kernel.setNonce(nonceKey, 100);

        // Trying to set a lower sequence should revert (seq must be > current)
        vm.expectRevert(InvalidNonce.selector);
        kernel.setNonce(nonceKey, 50);
    }
}
