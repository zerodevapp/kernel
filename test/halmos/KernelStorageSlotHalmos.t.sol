pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {
    SELECTOR_MANAGER_STORAGE_SLOT,
    MODULE_MANAGER_STORAGE_SLOT,
    EXECUTOR_MANAGER_STORAGE_SLOT,
    VALIDATION_MANAGER_STORAGE_SLOT,
    ERC1967_IMPLEMENTATION_SLOT
} from "src/types/Constants.sol";

/// @title KernelStorageSlotHalmos
/// @notice Halmos proofs that ERC-7201 storage slots do not collide
contract KernelStorageSlotHalmos is SymTest, Test {
    /// @notice Prove all storage slots are pairwise distinct
    function check_AllStorageSlotsDistinct() external pure {
        bytes32[5] memory slots = [
            SELECTOR_MANAGER_STORAGE_SLOT,
            MODULE_MANAGER_STORAGE_SLOT,
            EXECUTOR_MANAGER_STORAGE_SLOT,
            VALIDATION_MANAGER_STORAGE_SLOT,
            ERC1967_IMPLEMENTATION_SLOT
        ];

        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                assertTrue(slots[i] != slots[j], "storage slot collision");
            }
        }
    }

    /// @notice Prove SELECTOR_MANAGER_STORAGE_SLOT matches keccak256('kernel.v4.selector') - 1
    function check_SelectorManagerSlotDerivation() external pure {
        bytes32 expected = bytes32(uint256(keccak256("kernel.v4.selector")) - 1);
        assertEq(SELECTOR_MANAGER_STORAGE_SLOT, expected);
    }

    /// @notice Prove MODULE_MANAGER_STORAGE_SLOT matches keccak256('kernel.v4.module') - 1
    function check_ModuleManagerSlotDerivation() external pure {
        bytes32 expected = bytes32(uint256(keccak256("kernel.v4.module")) - 1);
        assertEq(MODULE_MANAGER_STORAGE_SLOT, expected);
    }

    /// @notice Prove EXECUTOR_MANAGER_STORAGE_SLOT matches keccak256('kernel.v4.executor') - 1
    function check_ExecutorManagerSlotDerivation() external pure {
        bytes32 expected = bytes32(uint256(keccak256("kernel.v4.executor")) - 1);
        assertEq(EXECUTOR_MANAGER_STORAGE_SLOT, expected);
    }

    /// @notice Prove VALIDATION_MANAGER_STORAGE_SLOT matches keccak256('kernel.v4.validation') - 1
    function check_ValidationManagerSlotDerivation() external pure {
        bytes32 expected = bytes32(uint256(keccak256("kernel.v4.validation")) - 1);
        assertEq(VALIDATION_MANAGER_STORAGE_SLOT, expected);
    }

    /// @notice Prove ERC1967 slot matches standard derivation
    function check_ERC1967SlotDerivation() external pure {
        bytes32 expected = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        assertEq(ERC1967_IMPLEMENTATION_SLOT, expected);
    }
}
