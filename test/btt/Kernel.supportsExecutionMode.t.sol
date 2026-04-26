// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @title Kernel.supportsExecutionMode BTT Tests
/// @notice Tests for supportsExecutionMode following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.supportsExecutionMode.tree
abstract contract Kernel_supportsExecutionMode is BTTModifiers {
    // State variable for exec type - set by modifier, used by _currentExecType()
    bytes1 internal _supportsExecType;

    function _encodeMode(bytes1 callType, bytes1 execType) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(callType, execType, bytes4(0), bytes4(0), bytes22(0)));
    }

    function _encodeModeWithCurrentExec(bytes1 callType) internal view returns (bytes32) {
        return _encodeMode(callType, _supportsExecType);
    }

    /*//////////////////////////////////////////////////////////////
                        EXECTYPE DEFAULT TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenExecTypeIsDEFAULT() {
        _supportsExecType = LibERC7579.EXECTYPE_DEFAULT;
        _;
    }

    function test_GivenCallTypeIsSINGLE() external givenExecTypeIsDEFAULT {
        bytes32 mode = _encodeModeWithCurrentExec(LibERC7579.CALLTYPE_SINGLE);
        assertTrue(kernel.supportsExecutionMode(mode), "Should support SINGLE + DEFAULT");
    }

    function test_GivenCallTypeIsBATCH() external givenExecTypeIsDEFAULT {
        bytes32 mode = _encodeModeWithCurrentExec(LibERC7579.CALLTYPE_BATCH);
        assertTrue(kernel.supportsExecutionMode(mode), "Should support BATCH + DEFAULT");
    }

    function test_GivenCallTypeIsDELEGATECALL() external givenExecTypeIsDEFAULT {
        bytes32 mode = _encodeModeWithCurrentExec(LibERC7579.CALLTYPE_DELEGATECALL);
        assertTrue(kernel.supportsExecutionMode(mode), "Should support DELEGATECALL + DEFAULT");
    }

    function test_GivenCallTypeIsAnyOtherValue() external givenExecTypeIsDEFAULT {
        // Use an unsupported call type (0x02)
        bytes32 mode = _encodeModeWithCurrentExec(bytes1(0x02));
        assertFalse(kernel.supportsExecutionMode(mode), "Should not support unsupported callType");
    }

    /*//////////////////////////////////////////////////////////////
                        EXECTYPE TRY TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenExecTypeIsTRY() {
        _supportsExecType = LibERC7579.EXECTYPE_TRY;
        _;
    }

    function test_GivenCallTypeIsSINGLE_GivenExecTypeIsTRY() external givenExecTypeIsTRY {
        bytes32 mode = _encodeModeWithCurrentExec(LibERC7579.CALLTYPE_SINGLE);
        assertTrue(kernel.supportsExecutionMode(mode), "Should support SINGLE + TRY");
    }

    function test_GivenCallTypeIsBATCH_GivenExecTypeIsTRY() external givenExecTypeIsTRY {
        bytes32 mode = _encodeModeWithCurrentExec(LibERC7579.CALLTYPE_BATCH);
        assertTrue(kernel.supportsExecutionMode(mode), "Should support BATCH + TRY");
    }

    function test_GivenCallTypeIsDELEGATECALL_GivenExecTypeIsTRY() external givenExecTypeIsTRY {
        bytes32 mode = _encodeModeWithCurrentExec(LibERC7579.CALLTYPE_DELEGATECALL);
        assertTrue(kernel.supportsExecutionMode(mode), "Should support DELEGATECALL + TRY");
    }

    function test_GivenCallTypeIsAnyOtherValue_GivenExecTypeIsTRY() external givenExecTypeIsTRY {
        // Use an unsupported call type (0x02)
        bytes32 mode = _encodeModeWithCurrentExec(bytes1(0x02));
        assertFalse(kernel.supportsExecutionMode(mode), "Should not support unsupported callType with TRY");
    }

    /*//////////////////////////////////////////////////////////////
                        UNSUPPORTED EXECTYPE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GivenExecTypeIsAnyOtherValue() external {
        // Use an unsupported exec type (0x02)
        bytes32 mode = _encodeMode(LibERC7579.CALLTYPE_SINGLE, bytes1(0x02));
        assertFalse(kernel.supportsExecutionMode(mode), "Should not support unsupported execType");
    }
}
