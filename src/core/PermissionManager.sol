pragma solidity ^0.8.0;

import {IValidator, IHook, IPolicy} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ValidationData} from "../interfaces/IAccount.sol";
import {IAccountExecute} from "../interfaces/IAccountExecute.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {
    ValidationId,
    PermissionData,
    ValidationMode,
    ValidationType,
    ValidatorLib,
    PassFlag
} from "../utils/ValidationTypeLib.sol";

import {PermissionId} from "../types/Types.sol";
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
import "forge-std/console.sol";

bytes32 constant VALIDATION_MANAGER_STORAGE_POSITION =
    0x7bcaa2ced2a71450ed5a9a1b4848e8e5206dbc3f06011e595f7f55428cc6f84f;

abstract contract ValidationManager is EIP712, SelectorManager {
    event ValidatorInstalled(IValidator validator, uint32 nonce);
    event PermissionInstalled(PermissionId permission, uint32 nonce);
    event NonceInvalidated(uint32 nonce);
    event ValidatorUninstalled(IValidator validator);
    event PermissionUninstalled(PermissionId permission);

    error InvalidMode();
    error InvalidValidator();
    error InvalidSignature();
    error PermissionDataTooLarge();
    error InvalidValidationType();
    error InvalidNonce();

    // CHECK is it better to have a group config?
    // erc7579 plugins
    struct ValidationConfig {
        uint32 nonce; // 4 bytes
        uint48 validFrom;
        uint48 validUntil;
        IHook hook; // 20 bytes address(1) : hook not required, address(0) : validator not installed
    }

    struct ValidationStorage {
        ValidationId rootValidator;
        uint32 currentNonce;
        uint32 validNonceFrom;
        mapping(ValidationId => ValidationConfig) validatorConfig;
        mapping(ValidationId => mapping(bytes4 => bool)) allowedSelectors;
        mapping(PermissionId => PermissionData[]) permissionData;
        mapping(PermissionId => IValidator) permissionValidator;
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

    function validatorConfig(ValidationId validator) external view returns (ValidationConfig memory) {
        return _validatorStorage().validatorConfig[validator];
    }

    function permissionData(ValidationId validator) external view returns (PermissionData[] memory) {
        PermissionId pId = ValidatorLib.getPermissionId(validator);
        return _validatorStorage().permissionData[pId];
    }

    function _validatorStorage() internal pure returns (ValidationStorage storage state) {
        assembly {
            state.slot := VALIDATION_MANAGER_STORAGE_POSITION
        }
    }

    function _invalidateNonce(uint32 nonce) internal {
        ValidationStorage storage state = _validatorStorage();
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
        assembly {
            permissionEnableData.offset := add(add(data.offset, 32), calldataload(data.offset))
            permissionEnableData.length := sub(calldataload(data.offset), 32)
        }
        if (permissionEnableData.length > 255 || permissionEnableData.length == 0) {
            revert PermissionDataTooLarge();
        }
        // require(lastEnableData);
        for (uint256 i = 0; i < permissionEnableData.length - 1; i++) {
            state.permissionData[permission].push(PermissionData.wrap(bytes22(permissionEnableData[i][0:22])));
            IPolicy(address(bytes20(permissionEnableData[i][2:22]))).onInstall(permissionEnableData[i][22:]);
        }
        // install permission
        IValidator permissionValidator =
            IValidator(address(bytes20(permissionEnableData[permissionEnableData.length - 1][0:20])));
        state.permissionValidator[permission] = permissionValidator;
        permissionValidator.onInstall(permissionEnableData[permissionEnableData.length - 1][20:]);
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

        (ValidationData policyCheck, IValidator validator) = _checkUserOpPolicy(vId, userOp, userOpSig);
        validationData = _intersectValidationData(validationData, policyCheck);
        validationData =
            _intersectValidationData(validationData, ValidationData.wrap(validator.validateUserOp(userOp, userOpHash)));
    }

    function _enableMode(ValidationId vId, bytes4 selector, bytes calldata packedData)
        internal
        returns (ValidationData, bytes calldata userOpSig)
    {
        ValidationStorage storage state = _validatorStorage();
        (bytes32 digest, bytes calldata enableSig) = _checkEnableSig(vId, selector, packedData);
        (IValidator validator, ValidationData validationData, bytes calldata sig) =
            _checkSignaturePolicy(state.rootValidator, address(this), digest, enableSig);

        bytes4 result = validator.isValidSignatureWithSender(address(this), digest, sig);
        if (result != 0x1626ba7e) {
            revert InvalidSignature();
        }

        assembly {
            userOpSig.offset := add(add(packedData.offset, 64), calldataload(add(packedData.offset, 160)))
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
            enableSig.offset := add(add(packedData.offset, 64), calldataload(add(packedData.offset, 128)))
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
        config.validFrom = uint48(bytes6(packedData[0:6]));
        config.validUntil = uint48(bytes6(packedData[6:12]));
        config.hook = IHook(address(bytes20(packedData[12:32])));
        config.nonce = state.currentNonce;

        assembly {
            validatorData.offset := add(add(packedData.offset, 64), calldataload(add(packedData.offset, 32)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            hookData.offset := add(add(packedData.offset, 64), calldataload(add(packedData.offset, 64)))
            hookData.length := calldataload(sub(hookData.offset, 32))
            selectorData.offset := add(add(packedData.offset, 64), calldataload(add(packedData.offset, 96)))
            selectorData.length := calldataload(sub(selectorData.offset, 32))
        }
        digest = _hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "Enable(bytes21 validationId,uint32 nonce,uint48 validFrom,uint48 validUntil,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                    ), // TODO: this to constant
                    ValidationId.unwrap(vId),
                    state.currentNonce,
                    config.validFrom,
                    config.validUntil,
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
        ValidationData validationData;
        PermissionId permission;
        PassFlag flag;
        IPolicy validator;
        bytes permSig;
    }

    function _checkUserOpPolicy(ValidationId vId, PackedUserOperation memory userOp, bytes calldata userOpSig)
        internal
        returns (ValidationData validationData, IValidator validator)
    {
        ValidationStorage storage state = _validatorStorage();
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_VALIDATOR) {
            return (ValidationData.wrap(0), ValidatorLib.getValidator(vId));
        } else if (ValidatorLib.getType(vId) == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = ValidatorLib.getPermissionId(vId);
            PermissionData[] storage permissions = state.permissionData[pId];
            for (uint256 i = 0; i < permissions.length; i++) {
                (PassFlag flag, IPolicy policy) = ValidatorLib.decodePermissionData(permissions[i]);
                uint8 idx = uint8(bytes1(userOpSig[0]));
                if (idx == i) {
                    // we are using uint64 length
                    uint256 length = uint64(bytes8(userOpSig[1:9]));
                    userOp.signature = userOpSig[9:9 + length];
                    userOpSig = userOpSig[9 + length:];
                } else if (idx < i) {
                    // signature is not in order
                    revert InvalidSignature();
                }
                if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_USEROP) == 0) {
                    validationData = _intersectValidationData(
                        validationData,
                        ValidationData.wrap(policy.checkUserOpPolicy(userOp, bytes32(PermissionId.unwrap(pId))))
                    );
                }
                userOp.signature = "";
            }
            return (validationData, state.permissionValidator[ValidatorLib.getPermissionId(vId)]);
        } else {
            revert InvalidValidationType();
        }
    }

    function _checkSignaturePolicy(ValidationId vId, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (IValidator validator, ValidationData validationData, bytes calldata)
    {
        ValidationStorage storage state = _validatorStorage();
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_VALIDATOR) {
            return (ValidatorLib.getValidator(vId), ValidationData.wrap(0), sig);
        } else if (ValidatorLib.getType(vId) == VALIDATION_TYPE_PERMISSION) {
            PermissionSigMemory memory mSig;
            mSig.permission = ValidatorLib.getPermissionId(vId);
            PermissionData[] storage permissions = state.permissionData[mSig.permission];
            for (uint256 i = 0; i < permissions.length; i++) {
                (mSig.flag, mSig.validator) = ValidatorLib.decodePermissionData(permissions[i]);
                mSig.idx = uint8(bytes1(sig[0]));
                if (mSig.idx == i) {
                    // we are using uint64 length
                    uint256 length = uint64(bytes8(sig[1:9]));
                    mSig.permSig = sig[9:9 + length];
                    sig = sig[9 + length:];
                } else if (mSig.idx < i) {
                    // signature is not in order
                    revert InvalidSignature();
                } else {
                    mSig.permSig = sig[0:0];
                }

                if (PassFlag.unwrap(mSig.flag) & PassFlag.unwrap(SKIP_SIGNATURE) == 0) {
                    mSig.validationData = _intersectValidationData(
                        mSig.validationData,
                        ValidationData.wrap(
                            mSig.validator.checkSignaturePolicy(
                                caller, digest, mSig.permSig, bytes32(PermissionId.unwrap(mSig.permission))
                            )
                        )
                    );
                }
            }
            return (state.permissionValidator[mSig.permission], mSig.validationData, sig);
        } else {
            revert InvalidValidationType();
        }
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
