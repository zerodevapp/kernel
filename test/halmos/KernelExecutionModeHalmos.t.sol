pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @title KernelExecutionModeHalmos
/// @notice Halmos proofs for execution mode support
contract KernelExecutionModeHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        MockValidator rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
    }

    /// @notice Prove supportsExecutionMode returns true for SINGLE+DEFAULT
    function check_SupportsSingleDefault() external view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        assertTrue(kernel.supportsExecutionMode(mode));
    }

    /// @notice Prove supportsExecutionMode returns true for SINGLE+TRY
    function check_SupportsSingleTry() external view {
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));
        assertTrue(kernel.supportsExecutionMode(mode));
    }

    /// @notice Prove supportsExecutionMode returns true for BATCH+DEFAULT
    function check_SupportsBatchDefault() external view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        assertTrue(kernel.supportsExecutionMode(mode));
    }

    /// @notice Prove supportsExecutionMode returns true for BATCH+TRY
    function check_SupportsBatchTry() external view {
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));
        assertTrue(kernel.supportsExecutionMode(mode));
    }

    /// @notice Prove supportsExecutionMode returns true for DELEGATECALL+DEFAULT
    function check_SupportsDelegatecallDefault() external view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        assertTrue(kernel.supportsExecutionMode(mode));
    }

    /// @notice Prove supportsExecutionMode returns true for DELEGATECALL+TRY
    function check_SupportsDelegatecallTry() external view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));
        assertTrue(kernel.supportsExecutionMode(mode));
    }

    /// @notice Prove supportsModule returns true for types 1-6
    function check_SupportsModuleTypes1to6() external view {
        for (uint256 i = 1; i <= 6; i++) {
            assertTrue(kernel.supportsModule(i));
        }
    }

    /// @notice Prove supportsModule returns false for type 0
    function check_DoesNotSupportModuleType0() external view {
        assertFalse(kernel.supportsModule(0));
    }

    /// @notice Prove supportsModule returns false for type 7+
    function check_DoesNotSupportModuleType7() external view {
        assertFalse(kernel.supportsModule(7));
    }

    /// @notice Prove supportsModule returns false for type 100
    function check_DoesNotSupportModuleType100() external view {
        assertFalse(kernel.supportsModule(100));
    }
}
