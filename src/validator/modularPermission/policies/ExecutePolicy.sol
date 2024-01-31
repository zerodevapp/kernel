pragma solidity ^0.8.0;

import "../IPolicy.sol";

struct ExecutionConfig {
    uint48 interval;
    uint48 count;
    ValidAfter startAt;
}

contract ExecutePolicy is IPolicy {
    mapping(address permissionValidator => mapping(bytes32 permissionId => mapping(address kernel => ExecutionConfig)))
        public executionConfigs;

    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata policyData)
        external
        payable
        override
    {
        uint48 delay = uint48(bytes6(policyData[0:6]));
        uint48 count = uint48(bytes6(policyData[6:12]));
        uint48 startAt = uint48(bytes6(policyData[12:18]));
        executionConfigs[msg.sender][permissionId][kernel] = ExecutionConfig(delay, count, ValidAfter.wrap(startAt));
    }

    function checkUserOpPolicy(address kernel, bytes32 permissionId, UserOperation calldata, bytes calldata)
        external
        payable
        override
        returns (ValidationData)
    {
        ExecutionConfig memory config = executionConfigs[msg.sender][permissionId][kernel];
        if (config.count == 0) {
            return SIG_VALIDATION_FAILED;
        }
        executionConfigs[msg.sender][permissionId][kernel].count = config.count - 1;
        executionConfigs[msg.sender][permissionId][kernel].startAt =
            ValidAfter.wrap(ValidAfter.unwrap(config.startAt) + config.interval);
        return packValidationData(config.startAt, ValidUntil.wrap(0));
    }

    function validateSignature(address, address, bytes32, bytes32, bytes32, bytes calldata)
        external
        view
        override
        returns (ValidationData)
    {
        return ValidationData.wrap(0);
    }
}
