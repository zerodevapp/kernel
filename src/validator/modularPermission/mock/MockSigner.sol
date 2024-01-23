pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData, ValidUntil, ValidAfter, packValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {ISigner} from "../ISigner.sol";

contract MockSigner is ISigner {
    ValidationData public validationData;
    mapping(bytes32 => uint256) public count;
    bytes public signerData;

    function mock(uint48 validAfter, uint48 validUntil, bool success) external {
        validationData = success
            ? packValidationData(ValidAfter.wrap(validAfter), ValidUntil.wrap(validUntil))
            : SIG_VALIDATION_FAILED;
    }

    function registerSigner(address, bytes32, bytes calldata data) external payable override {
        // do nothing
        signerData = data;
    }

    function validateUserOp(address, bytes32 permissionId, bytes32, bytes calldata)
        external
        payable
        override
        returns (ValidationData)
    {
        count[permissionId]++;
        return validationData;
    }

    function validateSignature(address, bytes32, bytes32, bytes calldata)
        external
        view
        override
        returns (ValidationData)
    {
        return validationData;
    }
}
