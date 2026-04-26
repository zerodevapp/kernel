// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {InvalidExecType, InvalidCallType} from "../types/Error.sol";

/// @title ExecutionManager
/// @author taek <leekt216@gmail.com>
/// @notice Dispatches ERC-7579 execution modes (single, batch, delegatecall) with default/try semantics.
abstract contract ExecutionManager {
    /// @notice Executes calldata according to the given ERC-7579 mode.
    /// @param mode Encodes call type (single/batch/delegatecall) and exec type (default/try).
    /// @param executionData Encoded execution data matching the call type.
    /// @return The array of return data from each executed call.
    function _execute(bytes32 mode, bytes calldata executionData) internal returns (bytes[] memory) {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        function() onRevert;
        if (execType == LibERC7579.EXECTYPE_DEFAULT) {
            onRevert = _onRevertThrow;
        } else if (execType == LibERC7579.EXECTYPE_TRY) {
            onRevert = _onRevertSilent;
        } else {
            revert InvalidExecType();
        }

        function(bytes calldata, function()) returns (bytes[] memory) executeFunction;
        if (callType == LibERC7579.CALLTYPE_SINGLE) {
            executeFunction = _executeCall;
        } else if (callType == LibERC7579.CALLTYPE_BATCH) {
            executeFunction = _executeBatchCall;
        } else if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            executeFunction = _executeDelegateCall;
        } else {
            revert InvalidCallType();
        }
        return executeFunction(executionData, onRevert);
    }

    /// @notice Executes a single call (target, value, data).
    function _executeCall(bytes calldata executionData, function() onRevert) internal returns (bytes[] memory results) {
        (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionData);
        bool success = _call(target, value, data);
        if (!success) {
            onRevert();
        }
        results = new bytes[](1);
        results[0] = _getReturn();
    }

    /// @notice Executes a delegatecall to a target with the given data.
    function _executeDelegateCall(bytes calldata executionData, function() onRevert)
        internal
        returns (bytes[] memory results)
    {
        (address delegate, bytes calldata data) = LibERC7579.decodeDelegate(executionData);
        bool success = _delegateCall(delegate, data);
        if (!success) {
            onRevert();
        }
        results = new bytes[](1);
        results[0] = _getReturn();
    }

    /// @notice Executes a batch of calls sequentially.
    function _executeBatchCall(bytes calldata executionData, function() onRevert)
        internal
        returns (bytes[] memory results)
    {
        bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
        uint256 length = pointers.length;
        results = new bytes[](length);
        unchecked {
            for (uint256 i; i < length; i++) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                bool success = _call(target, value, data);
                if (!success) {
                    onRevert();
                }
                results[i] = _getReturn();
            }
        }
    }

    /// @notice Copies the return data from the last external call into memory.
    function _getReturn() internal pure returns (bytes memory result) {
        assembly {
            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    /// @notice Bubbles up the revert data from the last failed call (EXECTYPE_DEFAULT behavior).
    function _onRevertThrow() internal pure {
        assembly {
            // Bubble up the revert if the call reverts.
            returndatacopy(0x00, 0x00, returndatasize())
            revert(0x00, returndatasize())
        }
    }

    /// @notice No-op revert handler (EXECTYPE_TRY behavior — swallows the revert).
    function _onRevertSilent() internal pure {}

    /// @notice Low-level call with value.
    function _call(address target, uint256 value, bytes memory callData) internal returns (bool success) {
        /// @solidity memory-safe-assembly
        assembly {
            let len := mload(callData)
            success := call(gas(), target, value, add(callData, 0x20), len, codesize(), 0x00)
        }
    }

    /// @notice Low-level delegatecall.
    function _delegateCall(address delegate, bytes calldata callData) internal returns (bool success) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, callData.offset, callData.length)
            // Forwards the `data` to `delegate` via delegatecall.
            success := delegatecall(gas(), delegate, ptr, callData.length, codesize(), 0x00)
        }
    }
}
