pragma solidity ^0.8.0;

import {IValidator, IHook, IPolicy, ISigner} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ValidationData, ValidAfter, ValidUntil, parseValidationData} from "../interfaces/IAccount.sol";
import {IAccountExecute} from "../interfaces/IAccountExecute.sol";
import {EIP712} from "solady/src/utils/EIP712.sol";
import {
    ValidationId,
    PolicyData,
    ValidationMode,
    ValidationType,
    ValidatorLib,
    PassFlag
} from "../utils/ValidationTypeLib.sol";

import {PermissionId, getValidationResult} from "../types/Types.sol";
import {_intersectValidationData} from "../utils/KernelValidationResult.sol";

import {
    VALIDATION_MODE_DEFAULT,
    VALIDATION_MODE_ENABLE,
    VALIDATION_TYPE_SUDO,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    SKIP_USEROP,
    SKIP_SIGNATURE
} from "../types/Constants.sol";

bytes32 constant VALIDATION_MANAGER_STORAGE_POSITION =
    0x7bcaa2ced2a71450ed5a9a1b4848e8e5206dbc3f06011e595f7f55428cc6f84f;
uint32 constant MAX_NONCE_INCREMENT_SIZE = 10;

abstract contract ValidationManager is EIP712, SelectorManager {
    event ValidatorInstalled(IValidator validator, uint32 nonce);
    event PermissionInstalled(PermissionId permission, uint32 nonce);
    event NonceInvalidated(uint32 nonce);
    event ValidatorUninstalled(IValidator validator);
    event PermissionUninstalled(PermissionId permission);
    event SelectorSet(bytes4 selector, ValidationId vId, bool allowed);

    error InvalidMode();
    error InvalidValidator();
    error InvalidSignature();
    error EnableNotApproved();
    error PolicySignatureOrderError();
    error SignerPrefixNotPresent();
    error PolicyDataTooLarge();
    error InvalidValidationType();
    error InvalidNonce();
    error PolicyFailed(uint256 i);
    error PermissionNotAlllowedForUserOp();
    error PermissionNotAlllowedForSignature();
    error NonceInvalidationError();

    // CHECK is it better to have a group config?
    // erc7579 plugins
    struct ValidationConfig {
        uint32 nonce; // 4 bytes
        IHook hook; // 20 bytes address(1) : hook not required, address(0) : validator not installed
    }

    struct PermissionConfig {
        PassFlag permissionFlag; // TODO: use this to show what is capable for permission
        ISigner signer;
        PolicyData[] policyData;
    }

    struct ValidationStorage {
        ValidationId rootValidator;
        uint32 currentNonce;
        uint32 validNonceFrom;
        mapping(ValidationId => ValidationConfig) validatorConfig;
        mapping(ValidationId => mapping(bytes4 => bool)) allowedSelectors;
        // validation = validator | permission
        // validator == 1 validator
        // permission == 1 validator + N policies
        mapping(PermissionId => PermissionConfig) permissionConfig;
    }

    function rootValidator() external view returns (ValidationId) {
        return _validatorStorage().rootValidator;
    }

    function currentNonce() external view returns (uint32) {
        return _validatorStorage().currentNonce;
    }

    function validNonceFrom() external view returns (uint32) {
        return _validatorStorage().validNonceFrom;
    }

    function isAllowedSelector(ValidationId vId, bytes4 selector) external view returns (bool) {
        return _validatorStorage().allowedSelectors[vId][selector];
    }

    function validatorConfig(ValidationId vId) external view returns (ValidationConfig memory) {
        return _validatorStorage().validatorConfig[vId];
    }

    function permissionConfig(ValidationId vId) external view returns (PermissionConfig memory) {
        PermissionId pId = ValidatorLib.getPermissionId(vId);
        return (_validatorStorage().permissionConfig[pId]);
    }

    function _validatorStorage() internal pure returns (ValidationStorage storage state) {
        assembly {
            state.slot := VALIDATION_MANAGER_STORAGE_POSITION
        }
    }

    function _invalidateNonce(uint32 nonce) internal {
        ValidationStorage storage state = _validatorStorage();
        if(state.currentNonce + MAX_NONCE_INCREMENT_SIZE < nonce) {
            revert NonceInvalidationError();
        }
        if (nonce <= state.validNonceFrom) {
            revert InvalidNonce();
        }
        state.validNonceFrom = nonce;
        if (state.currentNonce < state.validNonceFrom) {
            state.currentNonce = state.validNonceFrom;
        }
    }

    // allow installing multiple validators with same nonce
    function _installValidations(
        ValidationId[] calldata validators,
        ValidationConfig[] memory configs,
        bytes[] calldata validatorData,
        bytes[] calldata hookData
    ) internal {
        ValidationStorage storage state = _validatorStorage();
        for (uint256 i = 0; i < validators.length; i++) {
            _installValidation(validators[i], configs[i], validatorData[i], hookData[i]);
        }
        state.currentNonce++;
    }

    function _setSelector(ValidationId vId, bytes4 selector, bool allowed) internal {
        ValidationStorage storage state = _validatorStorage();
        state.allowedSelectors[vId][selector] = allowed;
        emit SelectorSet(selector, vId, allowed);
    }

    // for uninstall, we support uninstall for validator mode by calling onUninstall
    // but for permission mode, we do it naively by setting hook to address(0).
    // it is more recommended to use a nonce revoke to make sure the validator has been revoked
    // also, we are not calling hook.onInstall here
    function _uninstallValidation(ValidationId vId, bytes calldata validatorData) internal {
        ValidationStorage storage state = _validatorStorage();
        state.validatorConfig[vId].hook = IHook(address(0));
        ValidationType vType = ValidatorLib.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            validator.onUninstall(validatorData);
        }
    }

    function _installValidation(
        ValidationId vId,
        ValidationConfig memory config,
        bytes calldata validatorData,
        bytes calldata hookData
    ) internal {
        ValidationStorage storage state = _validatorStorage();
        if (config.hook == IHook(address(0))) {
            config.hook = IHook(address(1));
        }
        if (state.currentNonce != config.nonce || state.validatorConfig[vId].nonce >= config.nonce) {
            revert InvalidNonce();
        }
        state.validatorConfig[vId] = config;
        if (config.hook != IHook(address(1))) {
            config.hook.onInstall(hookData);
        }
        ValidationType vType = ValidatorLib.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            validator.onInstall(validatorData);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId permission = ValidatorLib.getPermissionId(vId);
            _installPermission(permission, validatorData);
        } else {
            revert InvalidValidationType();
        }
    }

    function _installPermission(PermissionId permission, bytes calldata data) internal {
        ValidationStorage storage state = _validatorStorage();
        bytes[] calldata permissionEnableData;
        bytes32 aa;
        assembly {
            permissionEnableData.offset := add(add(data.offset, 32), calldataload(data.offset))
            permissionEnableData.length := calldataload(sub(permissionEnableData.offset, 32))
            aa := permissionEnableData.length
        }
        // allow up to 0xfe, 0xff is dedicated for signer
        if (permissionEnableData.length > 254 || permissionEnableData.length == 0) {
            revert PolicyDataTooLarge();
        }
        for (uint256 i = 0; i < permissionEnableData.length - 1; i++) {
            state.permissionConfig[permission].policyData.push(PolicyData.wrap(bytes22(permissionEnableData[i][0:22])));
            IPolicy(address(bytes20(permissionEnableData[i][2:22]))).onInstall(
                abi.encodePacked(bytes32(PermissionId.unwrap(permission)), permissionEnableData[i][22:])
            );
        }
        // last permission data will be signer
        ISigner signer = ISigner(address(bytes20(permissionEnableData[permissionEnableData.length - 1][2:22])));
        state.permissionConfig[permission].signer = signer;
        state.permissionConfig[permission].permissionFlag =
            PassFlag.wrap(bytes2(permissionEnableData[permissionEnableData.length - 1][0:2]));
        signer.onInstall(
            abi.encodePacked(
                bytes32(PermissionId.unwrap(permission)), permissionEnableData[permissionEnableData.length - 1][22:]
            )
        );
    }

    function _doValidation(ValidationMode vMode, ValidationId vId, PackedUserOperation calldata op, bytes32 userOpHash)
        internal
        returns (ValidationData validationData)
    {
        ValidationStorage storage state = _validatorStorage();
        PackedUserOperation memory userOp = op;
        bytes calldata userOpSig = op.signature;

        if (vMode == VALIDATION_MODE_ENABLE) {
            bytes4 selector = bytes4(op.callData[0:4]) == IAccountExecute.executeUserOp.selector
                ? bytes4(op.callData[4:8])
                : bytes4(op.callData[0:4]);
            (validationData, userOpSig) = _enableMode(vId, selector, op.signature);
            userOp.signature = userOpSig;
            state.currentNonce++;
        }

        ValidationType vType = ValidatorLib.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            validationData = _intersectValidationData(
                validationData, ValidationData.wrap(ValidatorLib.getValidator(vId).validateUserOp(userOp, userOpHash))
            );
        } else {
            PermissionId pId = ValidatorLib.getPermissionId(vId);
            if (PassFlag.unwrap(state.permissionConfig[pId].permissionFlag) & PassFlag.unwrap(SKIP_USEROP) != 0) {
                revert PermissionNotAlllowedForUserOp();
            }
            (ValidationData policyCheck, ISigner signer) = _checkUserOpPolicy(pId, userOp, userOpSig);
            validationData = _intersectValidationData(validationData, policyCheck);
            validationData = _intersectValidationData(
                validationData,
                ValidationData.wrap(signer.checkUserOpSignature(bytes32(PermissionId.unwrap(pId)), userOp, userOpHash))
            );
        }
    }

    function _enableMode(ValidationId vId, bytes4 selector, bytes calldata packedData)
        internal
        returns (ValidationData validationData, bytes calldata userOpSig)
    {
        ValidationStorage storage state = _validatorStorage();
        (bytes32 digest, bytes calldata enableSig) = _checkEnableSig(vId, selector, packedData);
        ValidationType vType = ValidatorLib.getType(state.rootValidator);
        bytes4 result;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(state.rootValidator);
            result = validator.isValidSignatureWithSender(address(this), digest, enableSig);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = ValidatorLib.getPermissionId(state.rootValidator);
            ISigner signer;
            (signer, validationData, enableSig) = _checkSignaturePolicy(pId, address(this), digest, enableSig);
            result = signer.checkSignature(bytes32(PermissionId.unwrap(pId)), address(this), digest, enableSig);
        } else {
            revert InvalidValidationType();
        }
        if (result != 0x1626ba7e) {
            revert EnableNotApproved();
        }

        assembly {
            userOpSig.offset := add(add(packedData.offset, 52), calldataload(add(packedData.offset, 148)))
            userOpSig.length := calldataload(sub(userOpSig.offset, 32))
        }

        return (validationData, userOpSig);
    }

    function _checkEnableSig(ValidationId vId, bytes4 selector, bytes calldata packedData)
        internal
        returns (bytes32, bytes calldata enableSig)
    {
        (
            ValidationConfig memory config,
            bytes calldata validatorData,
            bytes calldata hookData,
            bytes calldata selectorData,
            bytes32 digest
        ) = _enableDigest(vId, packedData);
        assembly {
            enableSig.offset := add(add(packedData.offset, 52), calldataload(add(packedData.offset, 116)))
            enableSig.length := calldataload(sub(enableSig.offset, 32))
        }
        _installValidation(vId, config, validatorData, hookData);
        if (selectorData.length >= 4) {
            require(bytes4(selectorData[0:4]) == selector, "Invalid selector");
            if (selectorData.length >= 44) {
                // install selector with hook and target contract
                _installSelector(
                    selector,
                    address(bytes20(selectorData[4:24])),
                    IHook(address(bytes20(selectorData[24:44]))),
                    selectorData[44:]
                );
                _setSelector(vId, selector, true);
            } else {
                // set without install
                require(selectorData.length == 4, "Invalid selectorData");
                _setSelector(vId, selector, true);
            }
        }
        return (digest, enableSig);
    }

    function _enableDigest(ValidationId vId, bytes calldata packedData)
        internal
        view
        returns (
            ValidationConfig memory config,
            bytes calldata validatorData,
            bytes calldata hookData,
            bytes calldata selectorData,
            bytes32 digest
        )
    {
        ValidationStorage storage state = _validatorStorage();
        config.hook = IHook(address(bytes20(packedData[0:20])));
        config.nonce = state.currentNonce;

        assembly {
            validatorData.offset := add(add(packedData.offset, 52), calldataload(add(packedData.offset, 20)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            hookData.offset := add(add(packedData.offset, 52), calldataload(add(packedData.offset, 52)))
            hookData.length := calldataload(sub(hookData.offset, 32))
            selectorData.offset := add(add(packedData.offset, 52), calldataload(add(packedData.offset, 84)))
            selectorData.length := calldataload(sub(selectorData.offset, 32))
        }
        digest = _hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "Enable(bytes21 validationId,uint32 nonce,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                    ), // TODO: this to constant
                    ValidationId.unwrap(vId),
                    state.currentNonce,
                    config.hook,
                    keccak256(validatorData),
                    keccak256(hookData),
                    keccak256(selectorData)
                )
            )
        );
    }

    struct PermissionSigMemory {
        uint8 idx;
        uint256 length;
        ValidationData validationData;
        PermissionId permission;
        PassFlag flag;
        IPolicy policy;
        bytes permSig;
        address caller;
        bytes32 digest;
    }

    function _checkUserOpPolicy(PermissionId pId, PackedUserOperation memory userOp, bytes calldata userOpSig)
        internal
        returns (ValidationData validationData, ISigner signer)
    {
        ValidationStorage storage state = _validatorStorage();
        PolicyData[] storage policyData = state.permissionConfig[pId].policyData;
        for (uint256 i = 0; i < policyData.length; i++) {
            (PassFlag flag, IPolicy policy) = ValidatorLib.decodePolicyData(policyData[i]);
            uint8 idx = uint8(bytes1(userOpSig[0]));
            if (idx == i) {
                // we are using uint64 length
                uint256 length = uint64(bytes8(userOpSig[1:9]));
                userOp.signature = userOpSig[9:9 + length];
                userOpSig = userOpSig[9 + length:];
            } else if (idx < i) {
                // signature is not in order
                revert PolicySignatureOrderError();
            } else {
                userOp.signature = "";
            }
            if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_USEROP) == 0) {
                ValidationData vd =
                    ValidationData.wrap(policy.checkUserOpPolicy(bytes32(PermissionId.unwrap(pId)), userOp));
                address result = getValidationResult(vd);
                if (result != address(0)) {
                    revert PolicyFailed(i);
                }
                validationData = _intersectValidationData(validationData, vd);
            }
        }
        if (uint8(bytes1(userOpSig[0])) != 255) {
            revert SignerPrefixNotPresent();
        }
        userOp.signature = userOpSig[1:];
        return (validationData, state.permissionConfig[pId].signer);
    }

    function _checkSignaturePolicy(PermissionId pId, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (ISigner, ValidationData, bytes calldata)
    {
        ValidationStorage storage state = _validatorStorage();
        PermissionSigMemory memory mSig;
        mSig.permission = pId;
        mSig.caller = caller;
        mSig.digest = digest;
        _checkPermissionPolicy(mSig, state, sig);
        if (uint8(bytes1(sig[0])) != 255) {
            revert SignerPrefixNotPresent();
        }
        sig = sig[1:];
        return (state.permissionConfig[mSig.permission].signer, mSig.validationData, sig);
    }

    function _checkPermissionPolicy(
        PermissionSigMemory memory mSig,
        ValidationStorage storage state,
        bytes calldata sig
    ) internal view {
        PolicyData[] storage policyData = state.permissionConfig[mSig.permission].policyData;
        for (uint256 i = 0; i < policyData.length; i++) {
            (mSig.flag, mSig.policy) = ValidatorLib.decodePolicyData(policyData[i]);
            mSig.idx = uint8(bytes1(sig[0]));
            if (mSig.idx == i) {
                // we are using uint64 length
                mSig.length = uint64(bytes8(sig[1:9]));
                mSig.permSig = sig[9:9 + mSig.length];
                sig = sig[9 + mSig.length:];
            } else if (mSig.idx < i) {
                // signature is not in order
                revert PolicySignatureOrderError();
            } else {
                mSig.permSig = sig[0:0];
            }

            if (PassFlag.unwrap(mSig.flag) & PassFlag.unwrap(SKIP_SIGNATURE) == 0) {
                ValidationData vd = ValidationData.wrap(
                    mSig.policy.checkSignaturePolicy(
                        bytes32(PermissionId.unwrap(mSig.permission)), mSig.caller, mSig.digest, mSig.permSig
                    )
                );
                address result = getValidationResult(vd);
                if (result != address(0)) {
                    revert PolicyFailed(i);
                }

                mSig.validationData = _intersectValidationData(mSig.validationData, vd);
            }
        }
    }

    function _checkPermissionSignature(PermissionId pId, address caller, bytes32 hash, bytes calldata sig)
        internal
        view
        returns (bytes4)
    {
        (ISigner signer, ValidationData valdiationData, bytes calldata validatorSig) =
            _checkSignaturePolicy(pId, caller, hash, sig);
        (ValidAfter validAfter, ValidUntil validUntil,) = parseValidationData(ValidationData.unwrap(valdiationData));
        if (block.timestamp < ValidAfter.unwrap(validAfter) || block.timestamp > ValidUntil.unwrap(validUntil)) {
            return 0xffffffff;
        }
        return signer.checkSignature(bytes32(PermissionId.unwrap(pId)), caller, _toWrappedHash(hash), validatorSig);
    }

    function _toWrappedHash(bytes32 hash) internal view returns (bytes32) {
        ///     bytes32 digest = _hashTypedData(keccak256(abi.encode(
        ///         keccak256("Mail(address to,string contents)"),
        ///         mailTo,
        ///         keccak256(bytes(mailContents))
        ///     )));
        return _hashTypedData(keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash)));
    }
}
