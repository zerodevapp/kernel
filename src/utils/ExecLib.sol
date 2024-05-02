// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ExecMode, CallType, ExecType, ExecModeSelector, ExecModePayload} from "../types/Types.sol";
import {
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    EXECTYPE_DEFAULT,
    EXEC_MODE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_DELEGATECALL
} from "../types/Constants.sol";
import {Execution} from "../types/Structs.sol";

/**
 * @dev ExecLib is a helper library for execution
 */
library ExecLib {
    error ExecutionFailed();

    event TryExecuteUnsuccessful(uint256 batchExecutionindex, bytes result);

    function execute(ExecMode execMode, bytes calldata executionCalldata)
        internal
        returns (bytes[] memory returnData)
    {
        (CallType callType, ExecType execType,,) = decode(execMode);

        // check if calltype is batch or single
        if (callType == CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            Execution[] calldata executions = decodeBatch(executionCalldata);
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) returnData = execute(executions);
            else if (execType == EXECTYPE_TRY) returnData = tryExecute(executions);
            else revert("Unsupported");
        } else if (callType == CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (address target, uint256 value, bytes calldata callData) = decodeSingle(executionCalldata);
            returnData = new bytes[](1);
            bool success;
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) {
                returnData[0] = execute(target, value, callData);
            } else if (execType == EXECTYPE_TRY) {
                (success, returnData[0]) = tryExecute(target, value, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert("Unsupported");
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            returnData = new bytes[](1);
            address delegate = address(bytes20(executionCalldata[0:20]));
            bytes calldata callData = executionCalldata[20:];
            bool success;
            (success, returnData[0]) = executeDelegatecall(delegate, callData);
            if (execType == EXECTYPE_TRY) {
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else if (execType == EXECTYPE_DEFAULT) {
                if (!success) revert("Delegatecall failed");
            } else {
                revert("Unsupported");
            }
        } else {
            revert("Unsupported");
        }
    }

    function execute(Execution[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);

        for (uint256 i; i < length; i++) {
            Execution calldata _exec = executions[i];
            result[i] = execute(_exec.target, _exec.value, _exec.callData);
        }
    }

    function tryExecute(Execution[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);

        for (uint256 i; i < length; i++) {
            Execution calldata _exec = executions[i];
            bool success;
            (success, result[i]) = tryExecute(_exec.target, _exec.value, _exec.callData);
            if (!success) emit TryExecuteUnsuccessful(i, result[i]);
        }
    }

    function execute(address target, uint256 value, bytes calldata callData) internal returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            if iszero(call(gas(), target, value, result, callData.length, codesize(), 0x00)) {
                // Bubble up the revert if the call reverts.
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function tryExecute(address target, uint256 value, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            success := call(gas(), target, value, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    /// @dev Execute a delegatecall with `delegate` on this account.
    function executeDelegatecall(address delegate, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            // Forwards the `data` to `delegate` via delegatecall.
            success := delegatecall(gas(), delegate, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function decode(ExecMode mode)
        internal
        pure
        returns (CallType _calltype, ExecType _execType, ExecModeSelector _modeSelector, ExecModePayload _modePayload)
    {
        assembly {
            _calltype := mode
            _execType := shl(8, mode)
            _modeSelector := shl(48, mode)
            _modePayload := shl(80, mode)
        }
    }

    function encode(CallType callType, ExecType execType, ExecModeSelector mode, ExecModePayload payload)
        internal
        pure
        returns (ExecMode)
    {
        return ExecMode.wrap(
            bytes32(abi.encodePacked(callType, execType, bytes4(0), ExecModeSelector.unwrap(mode), payload))
        );
    }

    function encodeSimpleBatch() internal pure returns (ExecMode mode) {
        mode = encode(CALLTYPE_BATCH, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0x00));
    }

    function encodeSimpleSingle() internal pure returns (ExecMode mode) {
        mode = encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0x00));
    }

    function getCallType(ExecMode mode) internal pure returns (CallType calltype) {
        assembly {
            calltype := mode
        }
    }

    function decodeBatch(bytes calldata callData) internal pure returns (Execution[] calldata executionBatch) {
        /*
         * Batch Call Calldata Layout
         * Offset (in bytes)    | Length (in bytes) | Contents
         * 0x0                  | 0x4               | bytes4 function selector
        *  0x4                  | -                 |
        abi.encode(IERC7579Execution.Execution[])
         */
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let dataPointer := add(callData.offset, calldataload(callData.offset))

            // Extract the ERC7579 Executions
            executionBatch.offset := add(dataPointer, 32)
            executionBatch.length := calldataload(dataPointer)
        }
    }

    function encodeBatch(Execution[] memory executions) internal pure returns (bytes memory callData) {
        callData = abi.encode(executions);
    }

    function decodeSingle(bytes calldata executionCalldata)
        internal
        pure
        returns (address target, uint256 value, bytes calldata callData)
    {
        target = address(bytes20(executionCalldata[0:20]));
        value = uint256(bytes32(executionCalldata[20:52]));
        callData = executionCalldata[52:];
    }

    function encodeSingle(address target, uint256 value, bytes memory callData)
        internal
        pure
        returns (bytes memory userOpCalldata)
    {
        userOpCalldata = abi.encodePacked(target, value, callData);
    }

    function doFallback2771Static(address fallbackHandler) internal view returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            success := staticcall(gas(), fallbackHandler, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function doFallback2771Call(address target) internal returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            success := call(gas(), target, 0, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }
}
