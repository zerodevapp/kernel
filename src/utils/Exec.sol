// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.5 <0.9.0;

// solhint-disable no-inline-assembly

enum Operation {
    Call,
    DelegateCall
}

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 */
library Exec {
    function call(address to, uint256 value, bytes memory data)
        internal
        returns (bool success, bytes memory returnData)
    {
        assembly {
            success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            let len := returndatasize()
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    function staticcall(address to, bytes memory data) internal view returns (bool success, bytes memory returnData) {
        assembly {
            success := staticcall(gas(), to, add(data, 0x20), mload(data), 0, 0)
            let len := returndatasize()
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    function delegateCall(address to, bytes memory data) internal returns (bool success, bytes memory returnData) {
        assembly {
            success := delegatecall(gas(), to, add(data, 0x20), mload(data), 0, 0)
            let len := returndatasize()
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }
}
