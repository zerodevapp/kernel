pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";

import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";
import {ParamCondition, Operation} from "../common/Enums.sol";
import {ParamRule, SessionData, Permission, Call, ExecutionRule, ExecutionStatus, Nonces} from "../common/Structs.sol";
import "../common/Types.sol";

import {Kernel} from "../Kernel.sol";

contract SessionKeyValidator is IKernelValidator {
    mapping(address kernel => Nonces) public nonces;
    mapping(address sessionKey => mapping(address kernel => SessionData)) public sessionData;
    mapping(bytes32 permissionKey => mapping(address kernel => ExecutionStatus)) public executionStatus;

    function enable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes32 merkleRoot = bytes32(_data[20:52]);
        ValidAfter validAfter = ValidAfter.wrap(uint48(bytes6(_data[52:58])));
        ValidUntil validUntil = ValidUntil.wrap(uint48(bytes6(_data[58:64])));
        address paymaster = address(bytes20(_data[64:84]));
        uint256 nonce = uint256(bytes32(_data[84:116]));
        sessionData[sessionKey][msg.sender] = SessionData(merkleRoot, validAfter, validUntil, paymaster, nonce);
        require(nonce == ++nonces[msg.sender].lastNonce, "SessionKeyValidator: invalid nonce");
    }

    function invalidateNonce(uint128 nonce) public {
        require(nonce > nonces[msg.sender].invalidNonce, "SessionKeyValidator: invalid nonce");
        nonces[msg.sender].invalidNonce = nonce;
        if (nonces[msg.sender].lastNonce < nonce) {
            nonces[msg.sender].lastNonce = nonce;
        }
    }

    function disable(bytes calldata _data) external payable {
        // invalidate specific sessionKey
        if (_data.length == 20) {
            address sessionKey = address(bytes20(_data[0:20]));
            delete sessionData[sessionKey][msg.sender];
        } else if (_data.length == 16) {
            // invalidate all sessionKeys before specific nonce
            invalidateNonce(uint128(bytes16(_data[0:16])));
        } else {
            // invalidate all sessionKeys
            invalidateNonce(nonces[msg.sender].lastNonce);
        }
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

    function _verifyUserOpHash(address _sessionKey, ValidAfter validAfter, ValidUntil validUntil)
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
        return packValidationData(validAfter, validUntil);
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

    function validateUserOp(UserOperation calldata userOp, bytes32, uint256)
        external
        payable
        returns (ValidationData)
    {
        // userOp.signature = signer + signature + permission + merkleProof
        address sessionKey = address(bytes20(userOp.signature[0:20]));
        SessionData storage session = sessionData[sessionKey][msg.sender];
        // nonce starts from 1
        require(session.nonce > nonces[msg.sender].invalidNonce, "SessionKeyValidator: session key not enabled");
        _verifyPaymaster(userOp, session);

        // NOTE: although this is allowed in smart contract, it is guided not to use this feature in most usecases
        // instead of setting sudo approval to sessionKey, please set specific permission to sessionKey
        if (session.merkleRoot == bytes32(0)) {
            return _verifyUserOpHash(sessionKey, session.validAfter, session.validUntil);
        }

        bytes calldata callData = userOp.callData;
        if (
            bytes4(callData[0:4]) == Kernel.execute.selector
                || bytes4(callData[0:4]) == Kernel.executeDelegateCall.selector
        ) {
            (Permission calldata permission, bytes32[] calldata merkleProof) = _getPermission(userOp.signature[85:]);
            (ValidAfter validAfter, bool verifyFailed) = _verifyParam(sessionKey, callData, permission, merkleProof);
            if (verifyFailed) {
                return SIG_VALIDATION_FAILED;
            }
            return _verifyUserOpHash(sessionKey, validAfter, session.validUntil);
        } else if (bytes4(callData[0:4]) == Kernel.executeBatch.selector) {
            Permission[] calldata permissions = _getPermissions(userOp.signature[85:]);
            bytes32[][] calldata merkleProof = _getProofs(userOp.signature[85:]);
            (ValidAfter validAfter, bool verifyFailed) = _verifyParams(sessionKey, callData, permissions, merkleProof);
            if (verifyFailed) {
                return SIG_VALIDATION_FAILED;
            }
            return _verifyUserOpHash(sessionKey, validAfter, session.validUntil);
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _updateValidAfter(Permission calldata permission, bytes32 permissionKey)
        internal
        returns (ValidAfter validAfter)
    {
        if (permission.executionRule.interval == 0) {
            // no need to update validAfter
            validAfter = permission.executionRule.validAfter;
        } else {
            require(
                ValidAfter.unwrap(permission.executionRule.validAfter) != 0,
                "SessionKeyValidator: invalid execution rule"
            );
            // should update validAfter for executionStatus
            ExecutionStatus storage status = executionStatus[permissionKey][msg.sender];
            if (ValidAfter.unwrap(status.validAfter) != 0) {
                validAfter = ValidAfter.wrap(ValidAfter.unwrap(status.validAfter) + permission.executionRule.interval);
            } else {
                validAfter = permission.executionRule.validAfter;
            }
            status.validAfter = validAfter;
        }
        // update runs
        if (permission.executionRule.runs != 0) {
            ExecutionStatus storage status = executionStatus[permissionKey][msg.sender];
            status.runs += 1;
            require(status.runs <= permission.executionRule.runs, "SessionKeyValidator: runs exceeded");
        }
        return validAfter;
    }

    function _verifyParams(
        address sessionKey,
        bytes calldata callData,
        Permission[] calldata _permissions,
        bytes32[][] calldata _merkleProof
    ) internal returns (ValidAfter maxValidAfter, bool verifyFailed) {
        Call[] calldata calls;
        assembly {
            calls.offset := add(add(callData.offset, 0x24), calldataload(add(callData.offset, 4)))
            calls.length := calldataload(add(add(callData.offset, 4), calldataload(add(callData.offset, 4))))
        }
        uint256 i = 0;
        SessionData storage session = sessionData[sessionKey][msg.sender];
        maxValidAfter = session.validAfter;
        for (i = 0; i < calls.length; i++) {
            Call calldata call = calls[i];
            Permission calldata permission = _permissions[i];
            require(
                permission.target == address(0) || call.to == permission.target, "SessionKeyValidator: target mismatch"
            );
            require(uint256(bytes32(call.value)) <= permission.valueLimit, "SessionKeyValidator: value limit exceeded");
            require(verifyPermission(call.data, permission), "SessionKeyValidator: permission verification failed");
            ValidAfter validAfter =
                _updateValidAfter(permission, keccak256(abi.encodePacked(session.nonce, permission.index)));
            if (ValidAfter.unwrap(validAfter) > ValidAfter.unwrap(maxValidAfter)) {
                maxValidAfter = validAfter;
            }
            if (!MerkleProofLib.verify(_merkleProof[i], session.merkleRoot, keccak256(abi.encode(permission)))) {
                return (maxValidAfter, true);
            }
        }
    }

    function _verifyParam(
        address sessionKey,
        bytes calldata callData,
        Permission calldata _permission,
        bytes32[] calldata _merkleProof
    ) internal returns (ValidAfter validAfter, bool verifyFailed) {
        SessionData storage session = sessionData[sessionKey][msg.sender];
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
        validAfter = _updateValidAfter(_permission, keccak256(abi.encodePacked(session.nonce, _permission.index)));
        if (ValidAfter.unwrap(validAfter) < ValidAfter.unwrap(session.validAfter)) {
            validAfter = session.validAfter;
        }
        if (!MerkleProofLib.verify(_merkleProof, session.merkleRoot, keccak256(abi.encode(_permission)))) {
            return (validAfter, true);
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

    function validCaller(address, bytes calldata) external view returns (bool) {
        revert NotImplemented();
    }

    function validateSignature(bytes32, bytes calldata) external pure returns (ValidationData) {
        revert NotImplemented();
    }
}
