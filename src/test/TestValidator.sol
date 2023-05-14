// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/validator/IValidator.sol";

contract TestValidator is IKernelValidator {
    function validateSignature(bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }

    function validateUserOp(UserOperation calldata, bytes32, uint256) external pure override returns (uint256) {
        return 0;
    }

    function enable(bytes calldata) external override {}

    function disable(bytes calldata) external override {}
}
