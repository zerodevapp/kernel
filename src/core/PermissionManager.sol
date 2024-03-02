pragma solidity ^0.8.0;

import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
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
    PassFlag,
    Group
} from "../utils/ValidationTypeLib.sol";

import {PermissionId} from "../types/Types.sol";

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

abstract contract ValidationManager is EIP712, SelectorManager {
    event ValidatorInstalled(IValidator validator, Group group, uint32 nonce);
    event PermissionInstalled(PermissionId permission, Group group, uint32 nonce);
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
        bytes4 group; // 4 bytes = 2bytes for groupid, 2byte for skip flag
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
        mapping(PermissionId => PermissionData[]) permissionData;
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
        PermissionData lastEnableData =
            PermissionData.wrap(bytes22(permissionEnableData[permissionEnableData.length - 1][0:22]));
        // require(lastEnableData);
        for (uint256 i = 0; i < permissionEnableData.length; i++) {
            state.permissionData[permission].push(PermissionData.wrap(bytes22(permissionEnableData[i][0:22])));
            IValidator(address(bytes20(permissionEnableData[i][2:22]))).onInstall(permissionEnableData[i][22:]);
        }
    }

    function _doValidation(ValidationMode vMode, ValidationId vId, PackedUserOperation calldata op, bytes32 userOpHash)
        internal
        returns (ValidationData validationData)
    {
        ValidationStorage storage state = _validatorStorage();
        PackedUserOperation memory userOp = op;
        if (vMode == VALIDATION_MODE_ENABLE) {
            bytes4 selector = bytes4(op.callData[0:4]) == IAccountExecute.executeUserOp.selector
                ? bytes4(op.callData[4:8])
                : bytes4(op.callData[0:4]);
            bytes calldata userOpSig = _enableMode(vId, selector, op.signature);
            userOp.signature = userOpSig;
            state.currentNonce++;
        }
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_VALIDATOR) {
            validationData = ValidationData.wrap(ValidatorLib.getValidator(vId).validateUserOp(userOp, userOpHash));
        } else if (ValidatorLib.getType(vId) == VALIDATION_TYPE_PERMISSION) {
            PermissionData[] storage permissions = state.permissionData[ValidatorLib.getPermissionId(vId)];
            bytes calldata signature = op.signature;
            for (uint256 i = 0; i < permissions.length; i++) {
                (PassFlag flag, IValidator validator) = ValidatorLib.decodePermissionData(permissions[i]);
                uint8 idx = uint8(bytes1(signature[0]));
                if (idx == i) {
                    // we are using uint64 length
                    uint256 length = uint64(bytes8(signature[1:9]));
                    userOp.signature = signature[9:9 + length];
                    signature = signature[9 + length:];
                } else if (idx < i) {
                    // signature is not in order
                    revert InvalidSignature();
                }
                if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_USEROP) == 0) {
                    validationData = ValidationData.wrap(validator.validateUserOp(userOp, userOpHash));
                }
                userOp.signature = "";
            }
        } else {
            revert InvalidValidationType();
        }
    }

    function _enableMode(ValidationId vId, bytes4 selector, bytes calldata packedData)
        internal
        returns (bytes calldata userOpSig)
    {
        _checkEnableSig(vId, selector, packedData);
        assembly {
            userOpSig.offset := add(add(packedData.offset, 68), calldataload(add(packedData.offset, 164)))
            userOpSig.length := calldataload(sub(userOpSig.offset, 32))
        }
    }

    function _checkEnableSig(ValidationId vId, bytes4 selector, bytes calldata packedData) internal {
        ValidationStorage storage state = _validatorStorage();
        (
            ValidationConfig memory config,
            bytes calldata validatorData,
            bytes calldata hookData,
            bytes calldata selectorData,
            bytes32 digest
        ) = _enableDigest(vId, packedData);
        bytes calldata enableSig;
        assembly {
            enableSig.offset := add(add(packedData.offset, 68), calldataload(add(packedData.offset, 132)))
            enableSig.length := calldataload(sub(enableSig.offset, 32))
        }
        _installValidation(vId, config, validatorData, hookData);
        if (selectorData.length >= 4) {
            require(bytes4(selectorData[0:4]) == selector, "Invalid selector");
            if (selectorData.length >= 44) {
                // install selector with hook and target contract
                _installSelector(
                    selector,
                    config.group,
                    address(bytes20(selectorData[4:24])),
                    IHook(address(bytes20(selectorData[24:44]))),
                    selectorData[44:]
                );
            } else {
                require(selectorData.length == 4, "Invalid selectorData");
                // install selector without hook and target contract, only change group of selector
                _installSelector(selector, config.group, address(0), IHook(address(0)), selectorData[0:0]);
            }
        }
        bytes4 result = _validateSignature(state.rootValidator, address(this), digest, enableSig);
        if (result != 0x1626ba7e) {
            revert InvalidSignature();
        }
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
        config.group = bytes4(packedData[0:4]);
        config.validFrom = uint48(bytes6(packedData[4:10]));
        config.validUntil = uint48(bytes6(packedData[10:16]));
        config.hook = IHook(address(bytes20(packedData[16:36])));
        config.nonce = state.currentNonce;

        assembly {
            validatorData.offset := add(add(packedData.offset, 68), calldataload(add(packedData.offset, 36)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            hookData.offset := add(add(packedData.offset, 68), calldataload(add(packedData.offset, 68)))
            hookData.length := calldataload(sub(hookData.offset, 32))
            selectorData.offset := add(add(packedData.offset, 68), calldataload(add(packedData.offset, 100)))
            selectorData.length := calldataload(sub(selectorData.offset, 32))
        }
        digest = _hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "Enable(bytes21 validationId,uint32 nonce,bytes4 group,uint48 validFrom,uint48 validUntil,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                    ), // TODO: this to constant
                    ValidationId.unwrap(vId),
                    state.currentNonce,
                    config.group,
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

    function _validateSignature(ValidationId validator, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (bytes4 result)
    {
        ValidationStorage storage state = _validatorStorage();
        if (ValidatorLib.getType(validator) == VALIDATION_TYPE_VALIDATOR) {
            result = ValidatorLib.getValidator(validator).isValidSignatureWithSender(caller, digest, sig);
        } else if (ValidatorLib.getType(validator) == VALIDATION_TYPE_PERMISSION) {
            PermissionData[] storage permissions = state.permissionData[ValidatorLib.getPermissionId(validator)];
            for (uint256 i = 0; i < permissions.length; i++) {
                (PassFlag flag, IValidator vId) = ValidatorLib.decodePermissionData(permissions[i]);
                if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_SIGNATURE) == 0) {
                    result = vId.isValidSignatureWithSender(caller, digest, sig);
                }
            }
        } else {
            revert InvalidValidationType();
        }
    }
}
