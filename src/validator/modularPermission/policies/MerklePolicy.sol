pragma solidity ^0.8.0;

import "../IPolicy.sol";
import {Kernel} from "../../../Kernel.sol";
import {ParamCondition, Operation} from "../../../common/Enums.sol";
import {Call} from "../../../common/Structs.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

struct Permission {
    address target;
    bytes4 sig;
    uint256 valueLimit;
    ParamRule[] rules;
    Operation operation;
}

struct ParamRule {
    uint256 offset;
    ParamCondition condition;
    bytes32 param;
}

contract MerklePolicy is IPolicy {
    error MerklePolicyError(uint256 code); // todo: should policy revert instead of returning SIG_VALIDATION_FAILED?

    mapping(address permissionValidator => mapping(bytes32 => mapping(address => bytes32))) public merkleRoot;

    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata policyData) external payable {
        bytes32 root = bytes32(policyData[0:32]);
        merkleRoot[msg.sender][permissionId][kernel] = root;
    }

    function checkUserOpPolicy(
        address kernel,
        bytes32 permissionId,
        UserOperation calldata userOp,
        bytes calldata proof
    ) external payable returns (ValidationData) {
        bytes calldata callData = userOp.callData;
        bytes32 root = merkleRoot[msg.sender][permissionId][kernel];
        bytes4 sig = bytes4(callData[0:4]);
        if (sig == Kernel.execute.selector || sig == Kernel.executeDelegateCall.selector) {
            (Permission calldata permission, bytes32[] calldata merkleProof) = _getPermission(proof);
            bool verifyFailed = _verifyParam(root, callData, permission, merkleProof);
            if (verifyFailed) {
                revert MerklePolicyError(1); // merkle proof verification failed
            }
            return ValidationData.wrap(0);
        } else if (sig == Kernel.executeBatch.selector) {
            Permission[] calldata permissions = _getPermissions(proof);
            bytes32[][] calldata merkleProof = _getProofs(proof);
            bool verifyFailed = _verifyParams(root, callData, permissions, merkleProof);
            if (verifyFailed) {
                revert MerklePolicyError(1); // merkle proof verification failed
            }
            return ValidationData.wrap(0);
        } else {
            revert MerklePolicyError(0); // unknown selector
        }
    }

    function _verifyParams(
        bytes32 root,
        bytes calldata callData,
        Permission[] calldata _permissions,
        bytes32[][] calldata _merkleProof
    ) internal pure returns (bool verifyFailed) {
        Call[] calldata calls;
        assembly {
            calls.offset := add(add(callData.offset, 0x24), calldataload(add(callData.offset, 4)))
            calls.length := calldataload(add(add(callData.offset, 4), calldataload(add(callData.offset, 4))))
        }
        uint256 i = 0;
        for (i = 0; i < calls.length; i++) {
            Call calldata call = calls[i];
            Permission calldata permission = _permissions[i];
            require(
                permission.target == address(0) || call.to == permission.target, "SessionKeyValidator: target mismatch"
            );
            require(uint256(bytes32(call.value)) <= permission.valueLimit, "SessionKeyValidator: value limit exceeded");
            require(verifyPermission(call.data, permission), "SessionKeyValidator: permission verification failed");
            if (!MerkleProofLib.verify(_merkleProof[i], root, keccak256(abi.encode(permission)))) {
                return true;
            }
        }
    }

    // to parse batch execute permissions
    function _getPermissions(bytes calldata _sig) internal pure returns (Permission[] calldata permissions) {
        assembly {
            permissions.offset := add(add(_sig.offset, 0x20), calldataload(_sig.offset))
            permissions.length := calldataload(add(_sig.offset, calldataload(_sig.offset)))
        }
    }

    function _getProofs(bytes calldata _sig) internal pure returns (bytes32[][] calldata proofs) {
        assembly {
            proofs.length := calldataload(add(_sig.offset, calldataload(add(_sig.offset, 0x20))))
            proofs.offset := add(add(_sig.offset, 0x20), calldataload(add(_sig.offset, 0x20)))
        }
    }

    // to parse single execute permission
    function _getPermission(bytes calldata _sig)
        internal
        pure
        returns (Permission calldata permission, bytes32[] calldata merkleProof)
    {
        assembly {
            permission := add(_sig.offset, calldataload(_sig.offset))
            merkleProof.length := calldataload(add(_sig.offset, calldataload(add(_sig.offset, 0x20))))
            merkleProof.offset := add(add(_sig.offset, 0x20), calldataload(add(_sig.offset, 0x20)))
        }
    }

    function _verifyParam(
        bytes32 root,
        bytes calldata callData,
        Permission calldata _permission,
        bytes32[] calldata _merkleProof
    ) internal pure returns (bool verifyFailed) {
        bool isExecute = bytes4(callData[0:4]) == Kernel.execute.selector;
        require(
            _permission.target == address(0) || address(bytes20(callData[16:36])) == _permission.target,
            "SessionKeyValidator: target mismatch"
        );
        if (isExecute) {
            require(
                uint256(bytes32(callData[36:68])) <= _permission.valueLimit, "SessionKeyValidator: value limit exceeded"
            );
        } else {
            require(_permission.operation == Operation.DelegateCall, "SessionKeyValidator: operation mismatch");
        }
        bytes calldata data;
        uint8 dataParamOffset = isExecute ? 0x44 : 0x24;
        assembly {
            let dataOffset := add(add(callData.offset, 0x04), calldataload(add(callData.offset, dataParamOffset)))
            let length := calldataload(dataOffset)
            data.offset := add(dataOffset, 32)
            data.length := length
        }
        require(verifyPermission(data, _permission), "SessionKeyValidator: permission verification failed");
        if (!MerkleProofLib.verify(_merkleProof, root, keccak256(abi.encode(_permission)))) {
            return true;
        }
    }

    function verifyPermission(bytes calldata data, Permission calldata permission) internal pure returns (bool) {
        if (bytes4(data[0:4]) != permission.sig) return false;
        for (uint256 i = 0; i < permission.rules.length; i++) {
            ParamRule calldata rule = permission.rules[i];
            bytes32 param = bytes32(data[4 + rule.offset:4 + rule.offset + 32]);
            if (rule.condition == ParamCondition.EQUAL && param != rule.param) {
                return false;
            } else if (rule.condition == ParamCondition.GREATER_THAN && param <= rule.param) {
                return false;
            } else if (rule.condition == ParamCondition.LESS_THAN && param >= rule.param) {
                return false;
            } else if (rule.condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < rule.param) {
                return false;
            } else if (rule.condition == ParamCondition.LESS_THAN_OR_EQUAL && param > rule.param) {
                return false;
            } else if (rule.condition == ParamCondition.NOT_EQUAL && param == rule.param) {
                return false;
            }
        }
        return true;
    }

    function validateSignature(
        address kernel,
        address caller,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes32 rawHash,
        bytes calldata signature
    ) external view returns (ValidationData) {
        return ValidationData.wrap(0);
    }
}
