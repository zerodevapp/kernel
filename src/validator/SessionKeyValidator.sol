pragma solidity ^0.8.0;

import "solady/utils/ECDSA.sol";
import "solady/utils/MerkleProofLib.sol";

import "../interfaces/IValidator.sol";

import "../common/Constants.sol";
import "../common/Enum.sol";
import "../common/Structs.sol";
import "../common/Types.sol";

import {Kernel} from "../Kernel.sol";

import "forge-std/console.sol";

contract ExecuteSessionKeyValidator is IKernelValidator {
    mapping(address kernel => uint256) public invalidNonce;
    mapping(address sessionKey => mapping(address kernel => SessionData)) public sessionData;
    mapping(address sessionKey => mapping(uint32 index => mapping(address kernel => ValidAfter))) public
        executionValidAfter;

    function enable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes32 merkleRoot = bytes32(_data[20:52]);
        ValidAfter validAfter = ValidAfter.wrap(uint48(bytes6(_data[52:58])));
        ValidUntil validUntil = ValidUntil.wrap(uint48(bytes6(_data[58:64])));
        address paymaster = address(bytes20(_data[64:84]));
        uint256 approvedNonce = uint256(bytes32(_data[84:116]));
        sessionData[sessionKey][msg.sender] = SessionData(merkleRoot, validAfter, validUntil, paymaster, approvedNonce);
        require(approvedNonce == invalidNonce[msg.sender] + 1, "SessionKeyValidator: invalid nonce");
    }

    function disable(bytes calldata _data) external payable {
        // invalidate all nonces
        if (_data.length == 0) {
            invalidNonce[msg.sender]++;
            return;
        }
        // invalidate specific sessionKey
        address sessionKey = address(bytes20(_data[0:20]));
        delete sessionData[sessionKey][msg.sender];
    }

    function _verifyPaymaster(UserOperation calldata userOp, SessionData storage session) internal view {
        // to make this fully work with paymaster service, prepack the address of paymaster up front
        if (session.paymaster == address(1)) {
            // any paymaster
            require(userOp.paymasterAndData.length != 0, "SessionKeyValidator: paymaster not set");
        } else if (session.paymaster != address(0)) {
            // specific paymaster
            require(
                address(bytes20(userOp.paymasterAndData[0:20])) == session.paymaster,
                "SessionKeyValidator: paymaster mismatch"
            );
        }
    }

    function _verifyUserOpHash(address _sessionKey, SessionData storage _session)
        internal
        view
        returns (ValidationData)
    {
        bytes32 userOpHash;
        assembly {
            // 0x00 ~ 0x04 : sig
            // 0x04 ~ 0x24 : userOp.offset
            // 0x24 ~ 0x44 : userOpHash
            userOpHash := calldataload(0x24)
        }
        bytes calldata signature;
        assembly {
            //0x00 ~ 0x04 : selector
            //0x04 ~ 0x24 : userOp.offset
            //0x24 ~ 0x44 : userOpHash
            //0x44 ~ 0x64 : missingAccountFund
            //[userOp.offset + 0x04]
            //0x00 ~ 0x20 : sender
            //0x20 ~ 0x40 : nonce
            //0x40 ~ 0x60 : initCode
            //0x60 ~ 0x80 : callData
            //0x80 ~ 0xa0 : callGasLimit
            //0xa0 ~ 0xc0 : verificationGasLimit
            //0xc0 ~ 0xe0 : preVerificationGas
            //0xe0 ~ 0x100 : maxFeePerGas
            //0x100 ~ 0x120 : maxPriorityFeePerGas
            //0x120 ~ 0x140 : paymasterAndData
            //0x140 ~ 0x160 : signatureOffset
            //[signatureOffset + userOp.offset + 0x04]
            //[0x00 ~ 0x20] : length
            //[0x20 ~]      : signature
            let userOpOffset := add(calldataload(0x04), 0x04)
            let signatureOffset := add(calldataload(add(userOpOffset, 0x140)), add(userOpOffset, 0x34))
            signature.offset := signatureOffset
            signature.length := 0x41
        }
        if (_sessionKey != ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return packValidationData(_session.validAfter, _session.validUntil);
    }

    // to parse batch execute permissions
    function _getPermissions(bytes calldata _sig) internal view returns (Permission[] calldata permissions) {
        assembly {
            permissions.offset := add(add(_sig.offset, 0x20), calldataload(_sig.offset))
            permissions.length := calldataload(permissions.offset)
        }
    }

    // to parse single execute permission
    function _getPermission(bytes calldata _sig)
        internal
        view
        returns (Permission calldata permission, bytes32[] calldata merkleProof)
    {
        assembly {
            permission := add(_sig.offset, calldataload(_sig.offset))
            merkleProof.length := calldataload(add(_sig.offset, calldataload(add(_sig.offset, 0x20))))
            merkleProof.offset := add(add(_sig.offset, 0x20), calldataload(add(_sig.offset, 0x20)))
        }
    }

    function validateUserOp(UserOperation calldata userOp, bytes32, uint256)
        external
        payable
        returns (ValidationData)
    {
        // userOp.signature = signer + signature + permission + merkleProof
        address sessionKey = address(bytes20(userOp.signature[0:20]));
        SessionData storage session = sessionData[sessionKey][msg.sender];
        require(session.approvedNonce == invalidNonce[msg.sender] + 1, "SessionKeyValidator: session key not enabled");
        _verifyPaymaster(userOp, session);

        // NOTE: although this is allowed in smart contract, it is guided not to use this feature in most usecases
        // instead of setting sudo approval to sessionKey, please set specific permission to sessionKey
        if (session.merkleRoot == bytes32(0)) {
            return _verifyUserOpHash(sessionKey, session);
        }

        bytes calldata callData = userOp.callData;
        if (bytes4(callData[0:4]) == Kernel.execute.selector) {
            (Permission calldata permission, bytes32[] calldata merkleProof) = _getPermission(userOp.signature[85:]);
            require(
                permission.target == address(0) || address(bytes20(userOp.callData[16:36])) == permission.target,
                "SessionKeyValidator: target mismatch"
            );
            require(
                uint256(bytes32(userOp.callData[36:68])) <= permission.valueLimit,
                "SessionKeyValidator: value limit exceeded"
            );
            bytes calldata data;
            assembly {
                let dataOffset := add(add(callData.offset, 0x04), calldataload(add(callData.offset, 0x44)))
                let length := calldataload(dataOffset)
                data.offset := add(dataOffset, 32)
                data.length := length
            }
            require(verifyPermission(data, permission), "SessionKeyValidator: permission verification failed");
            ValidAfter validAfter = _updateValidAfter(permission, sessionKey);
            if (ValidAfter.unwrap(validAfter) < ValidAfter.unwrap(session.validAfter)) {
                validAfter = session.validAfter;
            }
            if (!MerkleProofLib.verify(merkleProof, session.merkleRoot, keccak256(abi.encode(permission)))) {
                return SIG_VALIDATION_FAILED;
            }
            return _verifyUserOpHash(sessionKey, session);
        } else if (bytes4(callData[0:4]) == Kernel.executeBatch.selector) {
            Permission[] calldata permissions = _getPermissions(userOp.signature[85:]);
            (, bytes32[] memory merkleProof, bool[] memory flags, uint256[] memory index) =
                abi.decode(userOp.signature[85:], (Permission[], bytes32[], bool[], uint256[]));
            bytes32[] memory leaves = _verifyParams(sessionKey, callData, permissions, index);
            if (!MerkleProofLib.verifyMultiProof(merkleProof, session.merkleRoot, leaves, flags)) {
                return SIG_VALIDATION_FAILED;
            }
            return _verifyUserOpHash(sessionKey, session);
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _updateValidAfter(Permission calldata permission, address sessionKey) internal returns (ValidAfter) {
        if (permission.executionRule.interval == 0) {
            // no need to update validAfter
            return ValidAfter.wrap(0);
        }
        uint48 validAfter = ValidAfter.unwrap(executionValidAfter[sessionKey][permission.index][msg.sender]);
        if (validAfter == 0) {
            validAfter = ValidAfter.unwrap(permission.executionRule.validAfter);
        }
        executionValidAfter[sessionKey][permission.index][msg.sender] =
            ValidAfter.wrap(validAfter + permission.executionRule.interval);
        return ValidAfter.wrap(validAfter);
    }

    function _verifyParams(
        address sessionKey,
        bytes calldata callData,
        Permission[] calldata _permissions,
        uint256[] memory index
    ) internal returns (bytes32[] memory leaves) {
        Call[] calldata calls;
        assembly {
            calls.offset := add(add(callData.offset, 0x24), calldataload(add(callData.offset, 4)))
            calls.length := calldataload(add(add(callData.offset, 4), calldataload(add(callData.offset, 4))))
        }
        //require(calls.length == permissions.length, "call length != permissions length"); ignore this since we don't care if calls.length < permissions.length
        //require(calls.length == index.length, "call length != index length");
        uint256 i = 0;
        leaves = _generateLeaves(index);
        ValidAfter maxValidAfter = sessionData[sessionKey][msg.sender].validAfter;
        for (i = 0; i < calls.length; i++) {
            Call calldata call = calls[i];
            Permission calldata permission = _permissions[i];
            require(
                permission.target == address(0) || call.to == permission.target, "SessionKeyValidator: target mismatch"
            );
            require(uint256(bytes32(call.value)) <= permission.valueLimit, "SessionKeyValidator: value limit exceeded");
            require(verifyPermission(call.data, permission), "SessionKeyValidator: permission verification failed");
            ValidAfter validAfter = _updateValidAfter(permission, sessionKey);
            if (ValidAfter.unwrap(validAfter) > ValidAfter.unwrap(maxValidAfter)) {
                maxValidAfter = validAfter;
            }
            leaves[index[i]] = keccak256(abi.encode(permission));
        }
    }

    function _generateLeaves(uint256[] memory _indexes) internal pure returns (bytes32[] memory leaves) {
        uint256 maxIndex;
        uint256 i = 0;
        for (i = 0; i < _indexes.length; i++) {
            if (_indexes[i] > maxIndex) {
                maxIndex = _indexes[i];
            }
        }
        leaves = new bytes32[](maxIndex + 1);
    }

    function verifyPermission(bytes calldata data, Permission calldata permission) internal view returns (bool) {
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

    function validCaller(address, bytes calldata) external pure returns (bool) {
        revert("SessionKeyValidator: not implemented");
    }

    function validateSignature(bytes32, bytes calldata) external pure returns (ValidationData) {
        revert("SessionKeyValidator: not implemented");
    }
}
