pragma solidity ^0.8.0;

import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ValidationData} from "../interfaces/IAccount.sol";
import {IAccountExecute} from "../interfaces/IAccountExecute.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import "forge-std/console.sol";

type ValidationMode is bytes1;

type ValidationId is bytes21;

type ValidationType is bytes1;

type PermissionData is bytes22; // 2bytes for flag on skip, 20 bytes for validator address

type Group is bytes4;

type GroupId is bytes2;

type PassFlag is bytes2;

PassFlag constant SKIP_USEROP = PassFlag.wrap(0x0001);
PassFlag constant SKIP_SIGNATURE = PassFlag.wrap(0x0002);

ValidationMode constant MODE_DEFAULT = ValidationMode.wrap(0x00);
ValidationMode constant MODE_ENABLE = ValidationMode.wrap(0x01);
ValidationType constant TYPE_SUDO = ValidationType.wrap(0x00);
ValidationType constant TYPE_VALIDATOR = ValidationType.wrap(0x01);
ValidationType constant TYPE_PERMISSION = ValidationType.wrap(0x02);

using {vModeEqual as ==} for ValidationMode global;
using {vTypeEqual as ==} for ValidationType global;
using {vIdentifierEqual as ==} for ValidationId global;
using {vModeNotEqual as !=} for ValidationMode global;
using {vTypeNotEqual as !=} for ValidationType global;
using {vIdentifierNotEqual as !=} for ValidationId global;

function vModeEqual(ValidationMode a, ValidationMode b) pure returns (bool) {
    return ValidationMode.unwrap(a) == ValidationMode.unwrap(b);
}

function vModeNotEqual(ValidationMode a, ValidationMode b) pure returns (bool) {
    return ValidationMode.unwrap(a) != ValidationMode.unwrap(b);
}

function vTypeEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) == ValidationType.unwrap(b);
}

function vTypeNotEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) != ValidationType.unwrap(b);
}

function vIdentifierEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) == ValidationId.unwrap(b);
}

function vIdentifierNotEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) != ValidationId.unwrap(b);
}

library ValidatorLib {
    function parseGroup(Group group) internal pure returns (GroupId groupId, PassFlag passFlag) {
        assembly {
            groupId := group
            passFlag := shl(16, group)
        }
    }

    function encodeGroup(GroupId groupId, PassFlag passFlag) internal pure returns (Group group) {
        assembly {
            group := or(groupId, shr(16, passFlag))
        }
    }

    function encodeFlag(bool skipUserOp, bool skipSignature) internal pure returns (PassFlag flag) {
        assembly {
            if skipUserOp { flag := 0x0001000000000000000000000000000000000000000000000000000000000000 }
            if skipSignature { flag := or(flag, 0x0002000000000000000000000000000000000000000000000000000000000000) }
        }
    }

    function encodeAsNonce(bytes1 mode, bytes1 vType, bytes20 ValidationIdWithoutType, uint16 nonceKey, uint64 nonce)
        internal
        pure
        returns (uint256 res)
    {
        assembly {
            res := nonce
            res := or(res, shl(64, nonceKey))
            res := or(res, shr(16, ValidationIdWithoutType))
            res := or(res, shr(8, vType))
            res := or(res, mode)
        }
    }

    function encodeAsNonceKey(bytes1 mode, bytes1 vType, bytes20 ValidationIdWithoutType, uint16 nonceKey)
        internal
        pure
        returns (uint192 res)
    {
        assembly {
            res := or(nonceKey, shr(80, ValidationIdWithoutType))
            res := or(res, shr(72, vType))
            res := or(res, shr(64, mode))
        }
    }

    function decode(uint256 nonce)
        internal
        pure
        returns (ValidationMode mode, ValidationType vType, ValidationId identifier)
    {
        // 2bytes mode (1byte currentMode, 1byte type)
        // 21bytes identifier
        // 1byte mode  | 1byte type | 20bytes identifierWithoutType | 2byte nonceKey | 8byte nonce == 32bytes
        assembly {
            mode := nonce
            vType := shl(8, nonce)
            identifier := shl(8, nonce) // identifier includes type
        }
    }

    function decodePermissionData(PermissionData data) internal pure returns (PassFlag flag, IValidator validator) {
        assembly {
            flag := data
            validator := shr(80, data)
        }
    }

    function validatorToIdentifier(IValidator validator) internal pure returns (ValidationId vId) {
        assembly {
            vId := 0x0100000000000000000000000000000000000000000000000000000000000000
            vId := or(vId, shl(88, validator))
        }
    }

    function getType(ValidationId validator) internal pure returns (ValidationType vType) {
        assembly {
            vType := validator
        }
    }

    function getValidator(ValidationId validator) internal pure returns (IValidator v) {
        assembly {
            v := shr(88, validator)
        }
    }

    function getPermissionValidator(PermissionData data) internal pure returns (IValidator vId) {
        assembly {
            vId := shr(80, data)
        }
    }

    function getPermissionSkip(PermissionData data) internal pure returns (PassFlag flag) {
        assembly {
            flag := data
        }
    }
}

abstract contract ValidationManager is EIP712, SelectorManager {
    error InvalidMode();
    error InvalidValidator();
    error InvalidSignature();

    // root validator cannot and should not be deleted
    ValidationId public rootValidator;

    uint32 public currentNonce;
    uint32 public validNonceFrom;

    // CHECK is it better to have a group config?
    // erc7579 plugins
    struct ValidatorConfig {
        bytes4 group; // 4 bytes = 2bytes for groupid, 2byte for skip flag
        uint32 nonce; // 4 bytes
        uint48 validFrom;
        uint48 validUntil;
        IHook hook; // 20 bytes address(1) : hook not required, address(0) : validator not installed
    }

    mapping(ValidationId validator => ValidatorConfig) public validatorConfig;

    // TODO add permission flag to skip validation
    mapping(ValidationId validator => PermissionData[]) public permissionData;

    function _invalidateNonce(uint32 nonce) internal {
        require(nonce > validNonceFrom, "Invalid nonce");
        validNonceFrom = nonce;
        if (currentNonce < validNonceFrom) {
            currentNonce = validNonceFrom;
        }
    }

    // allow installing multiple validators with same nonce
    function _installValidators(
        ValidationId[] calldata validators,
        ValidatorConfig[] memory configs,
        bytes[] calldata validatorData,
        bytes[] calldata hookData
    ) internal {
        // onlyEntrypointOrSelf
        for (uint256 i = 0; i < validators.length; i++) {
            _installValidator(validators[i], configs[i], validatorData[i], hookData[i]);
        }
        currentNonce++;
    }

    function _installValidator(
        ValidationId validator,
        ValidatorConfig memory config,
        bytes calldata data,
        bytes calldata hookData
    ) internal {
        if (address(config.hook) == address(0)) {
            config.hook = IHook(address(1));
        }
        validatorConfig[validator] = config;
        ValidationType vType = ValidatorLib.getType(validator);
        if (vType == TYPE_VALIDATOR) {
            IValidator(ValidatorLib.getValidator(validator)).onInstall(data);
        } else if (vType == TYPE_PERMISSION) {
            // TODO validate if this is working properly
            bytes[] calldata permissionEnableData;
            assembly {
                permissionEnableData.offset := add(add(data.offset, 32), calldataload(data.offset))
                permissionEnableData.length := sub(calldataload(data.offset), 32)
            }
            for (uint256 i = 0; i < permissionEnableData.length; i++) {
                permissionData[validator].push(PermissionData.wrap(bytes22(permissionEnableData[i][0:22])));
                IValidator(address(bytes20(permissionEnableData[i][2:22]))).onInstall(permissionEnableData[i][22:]);
            }
        } else {
            revert InvalidValidator();
        }
        if (address(config.hook) != address(1)) {
            config.hook.onInstall(hookData);
        }
    }

    function _doValidation(ValidationMode vMode, ValidationId vId, PackedUserOperation calldata op, bytes32 userOpHash)
        internal
        returns (ValidationData validationData)
    {
        PackedUserOperation memory userOp = op;
        if (vMode == MODE_ENABLE) {
            bytes4 selector = bytes4(op.callData[0:4]) == IAccountExecute.executeUserOp.selector
                ? bytes4(op.callData[4:8])
                : bytes4(op.callData[0:4]);
            bytes calldata userOpSig = _enableMode(vId, selector, op.signature);
            userOp.signature = userOpSig;
            currentNonce++;
        }
        if (ValidatorLib.getType(vId) == TYPE_VALIDATOR) {
            validationData = ValidationData.wrap(ValidatorLib.getValidator(vId).validateUserOp(userOp, userOpHash));
        } else if (ValidatorLib.getType(vId) == TYPE_PERMISSION) {
            PermissionData[] storage permissions = permissionData[vId];
            for (uint256 i = 0; i < permissions.length; i++) {
                (PassFlag flag, IValidator validator) = ValidatorLib.decodePermissionData(permissions[i]);
                if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_USEROP) == 0) {
                    validationData = ValidationData.wrap(validator.validateUserOp(userOp, userOpHash));
                }
                // skip
            }
        } else {
            revert InvalidValidator();
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
        (
            ValidatorConfig memory config,
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
        _installValidator(vId, config, validatorData, hookData);
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
        bytes4 result = _validateSignature(rootValidator, address(this), digest, enableSig);
        if (result != 0x1626ba7e) {
            revert InvalidSignature();
        }
    }

    function _enableDigest(ValidationId vId, bytes calldata packedData)
        internal
        view
        returns (
            ValidatorConfig memory config,
            bytes calldata validatorData,
            bytes calldata hookData,
            bytes calldata selectorData,
            bytes32 digest
        )
    {
        config.group = bytes4(packedData[0:4]);
        config.validFrom = uint48(bytes6(packedData[4:10]));
        config.validUntil = uint48(bytes6(packedData[10:16]));
        config.hook = IHook(address(bytes20(packedData[16:36])));
        config.nonce = currentNonce;

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
                    currentNonce,
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
        if (ValidatorLib.getType(validator) == TYPE_VALIDATOR) {
            result = ValidatorLib.getValidator(validator).isValidSignatureWithSender(caller, digest, sig);
        } else if (ValidatorLib.getType(validator) == TYPE_PERMISSION) {
            PermissionData[] storage permissions = permissionData[validator];
            for (uint256 i = 0; i < permissions.length; i++) {
                (PassFlag flag, IValidator vId) = ValidatorLib.decodePermissionData(permissions[i]);
                if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_SIGNATURE) == 0) {
                    result = vId.isValidSignatureWithSender(caller, digest, sig);
                }
            }
        } else {
            revert InvalidValidator();
        }
    }
}
