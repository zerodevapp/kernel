pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData, ValidUntil, ValidAfter, packValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {IPolicy} from "../IPolicy.sol";

contract MockPolicy is IPolicy {
    ValidationData public validationData;
    uint256 public sigConsume;
    mapping(bytes32 => uint256) public count;
    bytes public policyData;

    function mock(uint48 validAfter, uint48 validUntil, bool success, uint256 consume) external {
        validationData = success
            ? packValidationData(ValidAfter.wrap(validAfter), ValidUntil.wrap(validUntil))
            : SIG_VALIDATION_FAILED;
    }

    function registerPolicy(address, bytes32, bytes calldata data) external payable override {
        // do nothing
        policyData = data;
    }

    function validatePolicy(address, bytes32 permissionId, UserOperation calldata, bytes calldata)
        external
        payable
        override
        returns (ValidationData)
    {
        count[permissionId]++;
        return validationData;
    }

    function validateSignature(
        address kernel,
        address caller,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view override returns (ValidationData) {
        return validationData;
    }
}
