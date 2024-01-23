pragma solidity ^0.8.0;

import {ValidationData} from "src/common/Types.sol";
import {ValidAfter, ValidUntil, packValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";

interface ISigner {
    function registerSigner(address kernel, bytes32 permissionId, bytes calldata signerData) external payable;
    function validateUserOp(address kernel, bytes32 permissionId, bytes32 userOpHash, bytes calldata signature)
        external
        payable
        returns (ValidationData);
    function validateSignature(address kernel, bytes32 permissionId, bytes32 messageHash, bytes calldata signature)
        external
        view
        returns (ValidationData);
}
