pragma solidity ^0.8.0;

import "../IPolicy.sol";

contract SignaturePolicy is IPolicy {
    mapping(
        address permissionValidator
            => mapping(bytes32 permissionId => mapping(address requestor => mapping(address kernel => bool)))
    ) public allowedRequestor;

    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata policyData) external payable {
        address[] memory callers = abi.decode(policyData, (address[]));
        for (uint256 i = 0; i < callers.length; i++) {
            if (callers[i] == address(0)) {
                allowedRequestor[msg.sender][permissionId][kernel][kernel] = true;
            } else {
                allowedRequestor[msg.sender][permissionId][callers[i]][kernel] = true;
            }
        }
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
        bytes32 rawHash,
        bytes calldata signature
    ) external view override returns (ValidationData) {
        if (allowedRequestor[msg.sender][permissionId][caller][kernel]) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }
}
