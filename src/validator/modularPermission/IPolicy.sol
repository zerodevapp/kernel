pragma solidity ^0.8.0;

import {ValidationData, ValidUntil, ValidAfter, packValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";

interface IPolicy {
    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata policyData) external payable;
    function checkUserOpPolicy(
        address kernel,
        bytes32 permissionId,
        UserOperation calldata userOp,
        bytes calldata proofAndSig
    ) external payable returns (ValidationData);
    function validateSignature(
        address kernel,
        address caller,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes32 rawHash,
        bytes calldata signature
    ) external view returns (ValidationData);
}
