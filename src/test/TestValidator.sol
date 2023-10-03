// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../interfaces/IValidator.sol";
import "../common/Types.sol";

contract TestValidator is IKernelValidator {
    event TestValidateUserOp(bytes32 indexed opHash);
    event TestEnable(bytes data);
    event TestDisable(bytes data);

    mapping(address kernel => address) public caller;

    function sudoSetCaller(address _kernel, address _caller) external {
        caller[_kernel] = _caller;
    }

    function validateSignature(bytes32, bytes calldata) external pure override returns (ValidationData) {
        return ValidationData.wrap(0);
    }

    function validateUserOp(UserOperation calldata, bytes32 userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData)
    {
        emit TestValidateUserOp(userOpHash);
        return ValidationData.wrap(0);
    }

    function enable(bytes calldata data) external payable override {
        emit TestEnable(data);
    }

    function disable(bytes calldata data) external payable override {
        emit TestDisable(data);
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return _caller == caller[msg.sender];
    }
}
