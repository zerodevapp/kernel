pragma solidity ^0.8.0;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import "../types/Error.sol";

abstract contract ExecutionManager {
    function _execute(bytes32 mode, bytes calldata executionData) internal {
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

        function(bytes calldata, function()) executeFunction;
        if (callType == LibERC7579.CALLTYPE_SINGLE) {
            executeFunction = _executeCall;
        } else if (callType == LibERC7579.CALLTYPE_BATCH) {
            executeFunction = _executeBatchCall;
        } else if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            executeFunction = _executeDelegateCall;
        } else {
            revert InvalidCallType();
        }
        executeFunction(executionData, onRevert);
    }

    function _executeCall(bytes calldata executionData, function() onRevert) internal {
        (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionData);
        bool success = _call(target, value, data);
        if (!success) {
            onRevert();
        }
    }

    function _executeDelegateCall(bytes calldata executionData, function() onRevert) internal {
        (address delegate, bytes calldata data) = LibERC7579.decodeDelegate(executionData);
        bool success = _delegateCall(delegate, data);
        if (!success) {
            onRevert();
        }
    }

    function _executeBatchCall(bytes calldata executionData, function() onRevert) internal {
        bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
        uint256 length = pointers.length;
        bytes[] memory result = new bytes[](length);
        unchecked {
            for (uint256 i; i < length; i++) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                bool success = _call(target, value, data);
                if (!success) {
                    onRevert();
                }
            }
        }
    }

    function _getReturn() internal returns (bytes memory result) {
        assembly {
            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function _onRevertThrow() internal {
        assembly {
            // Bubble up the revert if the call reverts.
            returndatacopy(0x00, 0x00, returndatasize())
            revert(0x00, returndatasize())
        }
    }

    function _onRevertSilent() internal {}

    function _call(address target, uint256 value, bytes calldata callData) internal returns (bool success) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, callData.offset, callData.length)
            success := call(gas(), target, value, ptr, callData.length, codesize(), 0x00)
        }
    }

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
