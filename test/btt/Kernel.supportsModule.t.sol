// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";

/// @title Kernel.supportsModule BTT Tests
/// @notice Tests for supportsModule following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.supportsModule.tree
abstract contract Kernel_supportsModule is BTTModifiers {
    function test_GivenModuleTypeIdIs0() external {
        assertFalse(kernel.supportsModule(0), "Should not support moduleType 0");
    }

    function test_GivenModuleTypeIdIs1Validator() external {
        assertTrue(kernel.supportsModule(1), "Should support Validator (type 1)");
    }

    function test_GivenModuleTypeIdIs2Executor() external {
        assertTrue(kernel.supportsModule(2), "Should support Executor (type 2)");
    }

    function test_GivenModuleTypeIdIs3Fallback() external {
        assertTrue(kernel.supportsModule(3), "Should support Fallback (type 3)");
    }

    function test_GivenModuleTypeIdIs4Hook() external {
        assertTrue(kernel.supportsModule(4), "Should support Hook (type 4)");
    }

    function test_GivenModuleTypeIdIs5Policy() external {
        assertTrue(kernel.supportsModule(5), "Should support Policy (type 5)");
    }

    function test_GivenModuleTypeIdIs6Signer() external {
        assertTrue(kernel.supportsModule(6), "Should support Signer (type 6)");
    }

    function test_GivenModuleTypeIdIs7OrGreater() external {
        assertFalse(kernel.supportsModule(7), "Should not support moduleType 7");
        assertFalse(kernel.supportsModule(8), "Should not support moduleType 8");
        assertFalse(kernel.supportsModule(100), "Should not support moduleType 100");
    }
}
