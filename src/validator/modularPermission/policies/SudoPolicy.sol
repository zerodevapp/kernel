pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData} from "src/common/Types.sol";
import {IPolicy} from "../IPolicy.sol";

contract SudoPolicy is IPolicy {
    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata data) external payable override {}

    function checkUserOpPolicy(address kernel, bytes32 permissionId, UserOperation calldata userOp, bytes calldata)
        external
        payable
        override
        returns (ValidationData)
    {
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
