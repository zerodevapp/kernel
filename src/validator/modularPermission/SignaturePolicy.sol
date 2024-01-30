pragma solidity ^0.8.0;

import "./IPolicy.sol";

contract SignaturePolicy is IPolicy {
    mapping(bytes32 => mapping(address => mapping(address => bool))) public allowedCaller;

    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata policyData) external payable {
        allowedCaller[permissionId][address(bytes20(policyData))][kernel] = true;
    }

    function checkUserOpPolicy(
        address kernel,
        bytes32 permissionId,
        UserOperation calldata userOp,
        bytes calldata policyProof
    ) external payable override returns (ValidationData) {
        // do nothing on userOp validation
        return ValidationData.wrap(0);
    }

    function validateSignature(
        address kernel,
        address caller,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view override returns (ValidationData) {
        if (allowedCaller[permissionId][caller][kernel]) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }
}
