pragma solidity ^0.8.0;

import "../IPolicy.sol";

// does not support nested parameters,
// only allow checking,
// 1. domain separator
// 2. typeHash
// 3. encodeData => only allows 32 bytes of parameter in encodeData, if you are dealing with dynamic value, you need to pass in the keccak256 hash of the value
struct EncodeDataRule {
    uint32 index;
    bytes32 value;
    ParamRule rule;
}

struct AllowedEIP712Params {
    bytes32 domainSeparator;
    bytes32 typeHash;
    EncodeDataRule encodeDataRule;
}

enum ParamRule {
    NA,
    Equal,
    NotEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual
}

contract EIP712Policy is IPolicy {
    mapping(
        bytes32 permissionId => mapping(address permissionValidator => mapping(address kernel => AllowedEIP712Params))
    ) public eip712Param;
    mapping(
        bytes32 permissionId
            => mapping(
                address permissionValidator => mapping(bytes32 encodeData => mapping(address kernel => EncodeDataRule))
            )
    ) public nextEncodeData;

    function registerPolicy(address _kernel, bytes32 _permissionId, bytes calldata _data) external payable override {
        bytes32 domainSeparator = bytes32(_data[0:32]);
        bytes32 typeHash = bytes32(_data[32:64]);
        uint32 index = uint32(bytes4(_data[64:68]));
        ParamRule rule = ParamRule(uint8(bytes1(_data[68])));
        bytes32 encodeData = bytes32(_data[69:101]);
        uint256 cursor = 101;
        EncodeDataRule memory encodeDataRule = EncodeDataRule(index, encodeData, rule);
        eip712Param[_permissionId][msg.sender][_kernel] = AllowedEIP712Params(domainSeparator, typeHash, encodeDataRule);
        while (cursor <= _data.length - 37) {
            index = uint32(bytes4(_data[cursor:cursor + 4]));
            rule = ParamRule(uint8(bytes1(_data[cursor + 4])));
            bytes32 nextEncodeParam = bytes32(_data[cursor + 5:cursor + 37]);
            nextEncodeData[_permissionId][msg.sender][encodeData][_kernel] =
                EncodeDataRule(index, nextEncodeParam, rule);
            cursor += 37;
        }
    }

    function checkUserOpPolicy(
        address _kernel,
        bytes32 _permissionId,
        UserOperation calldata _userOp,
        bytes calldata _policyProof
    ) external payable override returns (ValidationData) {
        // do nothing on userOp validation
        return ValidationData.wrap(0);
    }

    function validateSignature(
        address _kernel,
        address _caller,
        bytes32 _permissionId,
        bytes32 _messageHash,
        bytes32 _rawHash,
        bytes calldata _signature
    ) external view override returns (ValidationData) {
        AllowedEIP712Params memory allowedEIP712Params = eip712Param[_permissionId][msg.sender][_kernel];
        bytes32[] memory encodedData = new bytes32[](uint32(bytes4(_signature[64:68])));
        uint256 cursor = 68;
        for (uint32 i = 0; i < encodedData.length; i++) {
            encodedData[i] = bytes32(_signature[cursor:cursor + 32]);
            cursor += 32;
        }
        {
            bytes32 domainSeparator = bytes32(_signature[0:32]);
            bytes32 typeHash = bytes32(_signature[32:64]);
            if (
                allowedEIP712Params.domainSeparator | domainSeparator != domainSeparator
                    || allowedEIP712Params.typeHash | typeHash != typeHash
            ) {
                return SIG_VALIDATION_FAILED;
            }
            bytes32 structHash = keccak256(abi.encodePacked(typeHash, encodedData));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            require(digest == _rawHash, "digest != _rawHash");
        }
        EncodeDataRule memory encodeDataRule = allowedEIP712Params.encodeDataRule;
        while (encodeDataRule.rule != ParamRule.NA) {
            if (encodeDataRule.rule == ParamRule.Equal) {
                if (encodedData[encodeDataRule.index] != encodeDataRule.value) {
                    return SIG_VALIDATION_FAILED;
                }
            } else if (encodeDataRule.rule == ParamRule.NotEqual) {
                if (encodedData[encodeDataRule.index] == encodeDataRule.value) {
                    return SIG_VALIDATION_FAILED;
                }
            } else if (encodeDataRule.rule == ParamRule.GreaterThan) {
                if (encodedData[encodeDataRule.index] <= encodeDataRule.value) {
                    return SIG_VALIDATION_FAILED;
                }
            } else if (encodeDataRule.rule == ParamRule.GreaterThanOrEqual) {
                if (encodedData[encodeDataRule.index] < encodeDataRule.value) {
                    return SIG_VALIDATION_FAILED;
                }
            } else if (encodeDataRule.rule == ParamRule.LessThan) {
                if (encodedData[encodeDataRule.index] >= encodeDataRule.value) {
                    return SIG_VALIDATION_FAILED;
                }
            } else if (encodeDataRule.rule == ParamRule.LessThanOrEqual) {
                if (encodedData[encodeDataRule.index] > encodeDataRule.value) {
                    return SIG_VALIDATION_FAILED;
                }
            }
            encodeDataRule = nextEncodeData[_permissionId][_caller][encodeDataRule.value][_kernel];
        }
        return ValidationData.wrap(0);
    }
}
