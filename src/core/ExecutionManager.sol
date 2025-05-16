pragma solidity ^0.8.0;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";

contract ExecutionManager {
    error NotSupportedCallType();
    error NotSupportedExecType();
    function _execute(bytes32 mode, bytes calldata executionData) internal {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        function(bytes memory) onRevert;
        if(execType == LibERC7579.EXECTYPE_DEFAULT) {
            onRevert = _onRevertThrow;
        } else if(execType == LibERC7579.EXECTYPE_TRY) {
            onRevert = _onRevertSilent;
        } else {
            revert NotSupportedExecType();
        }

        function(bytes calldata, function(bytes memory)) executeFunction;
        if(callType == LibERC7579.CALLTYPE_SINGLE) {
            executeFunction = _executeCall;
        } else if(callType == LibERC7579.CALLTYPE_BATCH) {
            executeFunction = _executeBatchCall;
        } else if(callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            executeFunction = _executeDelegateCall;
//        } else if(callType == LibERC7579.CALLTYPE_STATICCALL) { TODO: let's deal with static call later
//            executeFunction = _executeStaticCall;
        } else {
            revert NotSupportedCallType();
        }
    }

    function _executeCall(bytes calldata executionData, function(bytes memory) onRevert) internal {
        (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionData);
        (bool success, bytes memory res) = _call(target, value, data);
        if(!success) {
            onRevert(res);
        }
    }

    function _executeDelegateCall(bytes calldata executionData, function(bytes memory) onRevert) internal {
        (address delegate, bytes calldata data) = LibERC7579.decodeDelegate(executionData);
        (bool success, bytes memory res) = _delegateCall(delegate, data);
        if(!success) {
            onRevert(res);
        }
    }

    function _executeBatchCall(bytes calldata executionData, function(bytes memory) onRevert) internal {
        bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
        uint256 length = pointers.length;
        bytes[] memory result = new bytes[](length);
        unchecked {
            for (uint256 i; i < length; i++) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                (bool success, bytes memory ret) = _call(target, value, data);
                onRevert(ret);
            }
        }
    }

    function _onRevertThrow(bytes memory revertData) internal {
        uint256 length = revertData.length;
        assembly {
            revert(revertData, length)
        }
    }

    function _onRevertSilent(bytes memory revertData) internal {
    }

    function _call(address target, uint256 value, bytes calldata callData) internal returns(bool success, bytes memory result){
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

    function _delegateCall(address delegate, bytes calldata callData) internal returns(bool success, bytes memory result){
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
}
