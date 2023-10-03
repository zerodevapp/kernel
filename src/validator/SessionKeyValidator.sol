pragma solidity ^0.8.0;

import "solady/utils/ECDSA.sol";
import "../interfaces/IValidator.sol";
import "solady/utils/MerkleProofLib.sol";
import "../common/Constants.sol";
import "../common/Enum.sol";
import "../common/Structs.sol";
import "../common/Types.sol";
import {Kernel} from "../Kernel.sol";

import "forge-std/console.sol";

contract ExecuteSessionKeyValidator is IKernelValidator {
    mapping(address sessionKey => mapping(address kernel => SessionData)) public sessionData;
    mapping(address sessionKey => mapping(uint32 index => mapping(address kernel => ValidAfter))) public executionValidAfter;

    function enable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes32 merkleRoot = bytes32(_data[20:52]);
        ValidAfter validAfter = ValidAfter.wrap(uint48(bytes6(_data[52:58])));
        ValidUntil validUntil = ValidUntil.wrap(uint48(bytes6(_data[58:64])));
        address paymaster = address(bytes20(_data[64:84]));
        sessionData[sessionKey][msg.sender] = SessionData(merkleRoot, validAfter, validUntil, paymaster, true);
    }

    function disable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        address kernel = msg.sender;
        sessionData[sessionKey][kernel].enabled = false;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        payable
        returns (ValidationData)
    {
        // userOp.signature = signer + signature + permission + merkleProof
        address sessionKey = address(bytes20(userOp.signature[0:20]));
        bytes calldata signature = userOp.signature[20:85];
        SessionData storage session = sessionData[sessionKey][msg.sender];
        require(session.enabled, "SessionKeyValidator: session key not enabled");
        if (session.merkleRoot == bytes32(0)) {
            // sessionKey allowed to execute any tx
            if(sessionKey != ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), signature)) {
                return SIG_VALIDATION_FAILED;
            }
            return packValidationData(session.validAfter, session.validUntil);
        }
        if (session.paymaster == address(1)) {
            require(userOp.paymasterAndData.length != 0, "SessionKeyValidator: paymaster not set");
        } else if (session.paymaster != address(0)) {
            require(
                address(bytes20(userOp.paymasterAndData[0:20])) == session.paymaster,
                "SessionKeyValidator: paymaster mismatch"
            );
        }

        bytes4 sig = bytes4(userOp.callData[0:4]);

        if(sig == Kernel.execute.selector) {
            (Permission memory permission, bytes32[] memory merkleProof) =
                abi.decode(userOp.signature[85:], (Permission, bytes32[]));
            require(
                permission.target == address(0) || address(bytes20(userOp.callData[16:36])) == permission.target,
                "SessionKeyValidator: target mismatch"
            );
            require(
                uint256(bytes32(userOp.callData[36:68])) <= permission.valueLimit,
                "SessionKeyValidator: value limit exceeded"
            );
            uint256 dataOffset = uint256(bytes32(userOp.callData[68:100])) + 4; // adding 4 for msg.sig
            uint256 dataLength = uint256(bytes32(userOp.callData[dataOffset:dataOffset + 32]));
            bytes calldata data = userOp.callData[dataOffset + 32:dataOffset + 32 + dataLength];

            ValidAfter maxValidAfter = session.validAfter;
            if(permission.executionRule.interval != 0) {
                ValidAfter validAfter = executionValidAfter[sessionKey][permission.index][msg.sender];
                if(ValidAfter.unwrap(validAfter) == 0) {
                    validAfter = ValidAfter.wrap(
                        ValidAfter.unwrap(permission.executionRule.validAfter) + permission.executionRule.interval
                    );
                } else {
                    validAfter = ValidAfter.wrap(
                        uint48(ValidAfter.unwrap(validAfter)) + permission.executionRule.interval
                    );
                }
                executionValidAfter[sessionKey][permission.index][msg.sender] = validAfter;
                if(ValidAfter.unwrap(validAfter) > ValidAfter.unwrap(maxValidAfter)) {
                    maxValidAfter = validAfter;
                }
            }
            bool result = MerkleProofLib.verify(merkleProof, session.merkleRoot, keccak256(abi.encode(permission)))
            && (sessionKey == ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), signature));
            if (!result) {
                return SIG_VALIDATION_FAILED;
            }
            return packValidationData(maxValidAfter, session.validUntil);
        } else if (sig == Kernel.executeBatch.selector) {
            (Permission[] memory permissions, bytes32[] memory merkleProof, bool[] memory flags, uint256[] memory index) =
                abi.decode(userOp.signature[85:], (Permission[], bytes32[], bool[], uint256[]));
            Call[] calldata calls;
            bytes calldata callData = userOp.callData;
            assembly {
                calls.offset := add(add(callData.offset,4), calldataload(add(callData.offset,4)))
                calls.length := calldataload(calls.offset)
            }
            require(calls.length == permissions.length, "call length != permissions length");
            require(calls.length == index.length, "call length != index length");
            uint256 maxIndex;
            for(uint256 j = 0; j < index.length; j++) {
                if (index[j] > maxIndex) {
                    maxIndex = index[j];
                }
            }
            bytes32[] memory leaves = new bytes32[](maxIndex + 1);
            ValidAfter maxValidAfter = session.validAfter;
            for (uint256 i = 0; i < calls.length; i++) {
                //Call calldata callInfo;
                uint256 callInfoOffset;
                address to;
                uint256 value;
                bytes calldata data;
                assembly("memory-safe") {
                    callInfoOffset := add(add(calls.offset,0x20), calldataload(add(add(calls.offset, 0x20), mul(i, 0x20))))
                    to := calldataload(callInfoOffset)
                    value := calldataload(add(callInfoOffset, 0x20))
                    data.offset := add(add(callInfoOffset,0x20), calldataload(add(callInfoOffset, 0x40)))
                    data.length := calldataload(sub(data.offset, 0x20))
                }
                Permission memory permission = permissions[i];
                require(
                    permission.target == address(0) || to == permission.target,
                    "SessionKeyValidator: target mismatch"
                );
                require(
                    uint256(bytes32(value)) <= permission.valueLimit,
                    "SessionKeyValidator: value limit exceeded"
                );
                require(verifyPermission(data, permission), "SessionKeyValidator: permission verification failed");
                leaves[index[i]] = keccak256(abi.encode(permission));
                if(permission.executionRule.interval != 0) {
                    ValidAfter validAfter = executionValidAfter[sessionKey][permission.index][msg.sender];
                    if(ValidAfter.unwrap(validAfter) == 0) {
                        validAfter = ValidAfter.wrap(
                            ValidAfter.unwrap(permission.executionRule.validAfter) + permission.executionRule.interval
                        );
                    } else {
                        validAfter = ValidAfter.wrap(
                            uint48(ValidAfter.unwrap(validAfter)) + permission.executionRule.interval
                        );
                    }
                    executionValidAfter[sessionKey][permission.index][msg.sender] = validAfter;
                    if(ValidAfter.unwrap(validAfter) > ValidAfter.unwrap(maxValidAfter)) {
                        maxValidAfter = validAfter;
                    }
                }
            }
            bool result = MerkleProofLib.verifyMultiProof(merkleProof, session.merkleRoot, leaves, flags)
            && (sessionKey == ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), signature));
            if (!result) {
                return SIG_VALIDATION_FAILED;
            }
            return packValidationData(maxValidAfter, session.validUntil);
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function verifyPermission(bytes calldata data, Permission memory permission) internal view returns (bool) {
        if (bytes4(data[0:4]) != permission.sig) return false;
        for (uint256 i = 0; i < permission.rules.length; i++) {
            ParamRule memory rule = permission.rules[i];
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

    function validCaller(address, bytes calldata) external pure returns (bool) {
        revert("SessionKeyValidator: not implemented");
    }

    function validateSignature(bytes32, bytes calldata) external pure returns (ValidationData) {
        revert("SessionKeyValidator: not implemented");
    }
}
