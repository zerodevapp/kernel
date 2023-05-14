// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/validator/IValidator.sol";

contract TestValidator is IKernelValidator {
    event TestValidateUserOp(bytes32 indexed opHash);
    event TestEnable(bytes data);
    event TestDisable(bytes data);

    function validateSignature(bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }

    function validateUserOp(UserOperation calldata, bytes32 userOpHash, uint256) external override returns (uint256) {
        emit TestValidateUserOp(userOpHash);
        return 0;
    }

    function enable(bytes calldata data) external override {
        emit TestEnable(data);
    }

    function disable(bytes calldata data) external override {
        emit TestDisable(data);
    }
}
