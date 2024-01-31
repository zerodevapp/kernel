pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData, ValidUntil, ValidAfter, packValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {IPolicy} from "../IPolicy.sol";

contract GasPolicy is IPolicy {
    struct GasPolicyConfig {
        uint128 allowed;
        bool enforcePaymaster;
        address allowedPaymaster;
    }

    mapping(address permissionValidator => mapping(bytes32 permissionId => mapping(address kernel => GasPolicyConfig)))
        public gasPolicyConfig;

    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata data) external payable override {
        (uint128 allowed, bool enforcePaymaster, address allowedPaymaster) = abi.decode(data, (uint128, bool, address));
        gasPolicyConfig[msg.sender][permissionId][kernel] = GasPolicyConfig(allowed, enforcePaymaster, allowedPaymaster);
    }

    function checkUserOpPolicy(address kernel, bytes32 permissionId, UserOperation calldata userOp, bytes calldata)
        external
        payable
        override
        returns (ValidationData)
    {
        uint128 maxAmount = uint128(
            (userOp.preVerificationGas + userOp.verificationGasLimit + userOp.callGasLimit) * userOp.maxFeePerGas
        );
        if (gasPolicyConfig[msg.sender][permissionId][kernel].enforcePaymaster) {
            if (
                gasPolicyConfig[msg.sender][permissionId][kernel].allowedPaymaster != address(0)
                    && address(bytes20(userOp.paymasterAndData[0:20]))
                        != gasPolicyConfig[msg.sender][permissionId][kernel].allowedPaymaster
            ) {
                return SIG_VALIDATION_FAILED;
            }
        }
        if (maxAmount > gasPolicyConfig[msg.sender][permissionId][kernel].allowed) {
            return SIG_VALIDATION_FAILED;
        }
        gasPolicyConfig[msg.sender][permissionId][kernel].allowed -= maxAmount;
        return ValidationData.wrap(0);
    }

    function validateSignature(
        address kernel,
        address caller,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes32 rawHash,
        bytes calldata signature
    ) external view override returns (ValidationData) {
        return ValidationData.wrap(0);
    }
}
