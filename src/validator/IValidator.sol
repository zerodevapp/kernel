// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/interfaces/UserOperation.sol";

interface IKernelValidator {
    function enable(bytes calldata _data) external;

    function disable(bytes calldata _data) external;

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        returns (uint256);

    function validateSignature(bytes32 hash, bytes calldata signature) external view returns (uint256);
}

// 3 modes
// 1. default mode, use preset validator for the kernel
// 2. enable mode, enable a new validator for given action and use it for current userOp
// 3. sudo mode, use default plugin for current userOp
