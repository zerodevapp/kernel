// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";

abstract contract Kernel_viewFunctions is BTTModifiers {
    // State variable for nonce key - set by modifier, used in tests
    uint192 internal _nonceKey;

    function test_WhenCallingValidNonceFrom() external {
        // it should return the current validNonceFrom value
        uint64 initialValue = kernel.validNonceFrom();
        assertEq(initialValue, 0, "Initial validNonceFrom should be 0");

        // Set a new value and verify
        vm.prank(address(ep));
        kernel.setValidNonceFrom(100);

        uint64 newValue = kernel.validNonceFrom();
        assertEq(newValue, 100, "validNonceFrom should be updated to 100");
    }

    modifier whenCallingNonce() {
        _nonceKey = 1;
        _;
    }

    function test_GivenValidNonceFromIsZero() external whenCallingNonce {
        // it should return the current sequence number for the key
        uint256 nonceValue = kernel.nonce(_nonceKey);

        // With validNonceFrom = 0, nonce should be (key << 64) + seq
        // Initial seq should be 0
        assertEq(nonceValue, uint256(_nonceKey) << 64, "Nonce should be key shifted left by 64 bits");
    }

    function test_GivenValidNonceFromIsGreaterThanTheSequence() external whenCallingNonce {
        // it should return validNonceFrom as the sequence
        // Set validNonceFrom to a value
        vm.prank(address(ep));
        kernel.setValidNonceFrom(50);

        uint256 nonceValue = kernel.nonce(_nonceKey);

        // With validNonceFrom = 50 > seq (0), nonce should use validNonceFrom as seq
        assertEq(nonceValue, (uint256(_nonceKey) << 64) + 50, "Nonce should use validNonceFrom as sequence");
    }

    function test_WhenCallingRegistry() external {
        // it should return the registry address
        address registryAddr = kernel.registry();
        // Default registry is address(0)
        assertEq(registryAddr, address(0), "Default registry should be address(0)");
    }
}
