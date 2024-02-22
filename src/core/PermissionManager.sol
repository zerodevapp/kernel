pragma solidity ^0.8.0;

import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {ValidationData} from "../interfaces/IAccount.sol";
import {IAccountExecute} from "../interfaces/IAccountExecute.sol";
import {EIP712} from "solady/utils/EIP712.sol";

type ValidatorMode is bytes1;

type ValidatorIdentifier is bytes21;

type ValidatorType is bytes1;

type PermissionData is bytes22; // 2bytes for flag on skip, 20 bytes for validator address

ValidatorMode constant MODE_DEFAULT = ValidatorMode.wrap(0x00);
ValidatorMode constant MODE_ENABLE = ValidatorMode.wrap(0x01);
ValidatorType constant TYPE_SUDO = ValidatorType.wrap(0x00);
ValidatorType constant TYPE_VALIDATOR = ValidatorType.wrap(0x01);
ValidatorType constant TYPE_PERMISSION = ValidatorType.wrap(0x02);

using {vModeEqual as ==} for ValidatorMode global;
using {vTypeEqual as ==} for ValidatorType global;
using {vIdentifierEqual as ==} for ValidatorIdentifier global;
using {vModeNotEqual as !=} for ValidatorMode global;
using {vTypeNotEqual as !=} for ValidatorType global;
using {vIdentifierNotEqual as !=} for ValidatorIdentifier global;

function vModeEqual(ValidatorMode a, ValidatorMode b) pure returns (bool) {
    return ValidatorMode.unwrap(a) == ValidatorMode.unwrap(b);
}

function vModeNotEqual(ValidatorMode a, ValidatorMode b) pure returns (bool) {
    return ValidatorMode.unwrap(a) != ValidatorMode.unwrap(b);
}

function vTypeEqual(ValidatorType a, ValidatorType b) pure returns (bool) {
    return ValidatorType.unwrap(a) == ValidatorType.unwrap(b);
}

function vTypeNotEqual(ValidatorType a, ValidatorType b) pure returns (bool) {
    return ValidatorType.unwrap(a) != ValidatorType.unwrap(b);
}

function vIdentifierEqual(ValidatorIdentifier a, ValidatorIdentifier b) pure returns (bool) {
    return ValidatorIdentifier.unwrap(a) == ValidatorIdentifier.unwrap(b);
}

function vIdentifierNotEqual(ValidatorIdentifier a, ValidatorIdentifier b) pure returns (bool) {
    return ValidatorIdentifier.unwrap(a) != ValidatorIdentifier.unwrap(b);
}

library ValidatorLib {
    function encode(bytes1 mode, bytes1 vType, bytes20 validatorIdentifierWithoutType, uint16 nonceKey, uint64 nonce)
        internal
        pure
        returns (uint256 res)
    {
        assembly {
            res := nonce
            res := or(res, shl(64, nonceKey))
            res := or(res, shr(16, validatorIdentifierWithoutType))
            res := or(res, shr(8, vType))
            res := or(res, mode)
        }
    }

    function decode(uint256 nonce)
        internal
        pure
        returns (ValidatorMode mode, ValidatorType vType, ValidatorIdentifier identifier)
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

    function validatorToIdentifier(IValidator validator) internal pure returns (ValidatorIdentifier vId) {
        assembly {
            vId := 0x0100000000000000000000000000000000000000000000000000000000000000
            vId := or(vId, shl(88, validator))
        }
    }

    function getType(ValidatorIdentifier validator) internal pure returns (ValidatorType vType) {
        assembly {
            vType := validator
        }
    }

    function getValidator(ValidatorIdentifier validator) internal pure returns (IValidator v) {
        assembly {
            v := shr(88, validator)
        }
    }

    function getPermissionValidator(PermissionData data) internal pure returns (IValidator vId) {
        assembly {
            vId := data
        }
    }
}

abstract contract ValidationManager is EIP712, SelectorManager {
    error InvalidMode();
    error InvalidValidator();
    error InvalidSignature();

    // root validator cannot and should not be deleted
    ValidatorIdentifier public rootValidator;

    uint32 public currentNonce;
    uint32 public validNonceFrom;

    // CHECK is it better to have a group config?
    // erc7579 plugins
    struct ValidatorConfig {
        bytes4 group; // 4 bytes
        uint32 nonce; // 4 bytes
        uint48 validFrom;
        uint48 validUntil;
        IHook hook; // 20 bytes address(1) : hook not required, address(0) : validator not installed
    }

    mapping(ValidatorIdentifier validator => ValidatorConfig) public validatorConfig;

    // TODO add permission flag to skip validation
    mapping(ValidatorIdentifier validator => PermissionData[]) public permissionConfig;

    function _invalidateNonce(uint32 nonce) internal {
        require(nonce > validNonceFrom, "Invalid nonce");
        validNonceFrom = nonce;
        if (currentNonce < validNonceFrom) {
            currentNonce = validNonceFrom;
        }
    }

    // allow installing multiple validators with same nonce
    function _installValidators(
        ValidatorIdentifier[] calldata validators,
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
        ValidatorIdentifier validator,
        ValidatorConfig memory config,
        bytes calldata data,
        bytes calldata hookData
    ) internal {
        if (address(config.hook) == address(0)) {
            config.hook = IHook(address(1));
        }
        validatorConfig[validator] = config;
        ValidatorType vType = ValidatorLib.getType(validator);
        if (vType == TYPE_VALIDATOR) {
            IValidator(ValidatorLib.getValidator(validator)).onInstall(data);
        } else if (vType == TYPE_PERMISSION) {
            //TODO
            revert("NOT_IMPLEMENTED_PERMISSION_INSTALL");
        } else {
            revert InvalidValidator();
        }
        if (address(config.hook) != address(1)) {
            config.hook.onInstall(hookData);
        }
    }

    function _doValidation(
        ValidatorMode vMode,
        ValidatorIdentifier vId,
        PackedUserOperation calldata op,
        bytes32 userOpHash
    ) internal returns (ValidationData validationData) {
        PackedUserOperation memory userOp = op;
        if (vMode == MODE_ENABLE) {
            bytes4 selector = bytes4(op.signature[0:4]) == IAccountExecute.executeUserOp.selector
                ? bytes4(op.signature[4:8])
                : bytes4(op.signature[0:4]);
            bytes calldata userOpSig = _enableMode(vId, selector, op.signature);
            userOp.signature = userOpSig;
            currentNonce++;
        }
        if (ValidatorLib.getType(vId) == TYPE_VALIDATOR) {
            validationData = ValidationData.wrap(ValidatorLib.getValidator(vId).validateUserOp(userOp, userOpHash));
        } else if (ValidatorLib.getType(vId) == TYPE_PERMISSION) {
            // TODO
            revert("NOT_IMPLEMENTED_VALIDATION_PERMISSION");
        } else {
            revert InvalidValidator();
        }
    }

    function _enableMode(ValidatorIdentifier vId, bytes4 selector, bytes calldata packedData)
        internal
        returns (bytes calldata userOpSig)
    {
        _checkEnableValidatorSig(vId, selector, packedData);
        assembly {
            userOpSig.offset := add(add(packedData.offset, 32), calldataload(add(packedData.offset, 164)))
            userOpSig.length := calldataload(sub(userOpSig.offset, 32))
        }
    }

    function _checkEnableValidatorSig(ValidatorIdentifier vId, bytes4 selector, bytes calldata packedData) internal {
        if (ValidatorLib.getType(vId) != TYPE_VALIDATOR) {
            revert InvalidValidator();
        } else {
            (
                ValidatorConfig memory config,
                bytes calldata validatorData,
                bytes calldata hookData,
                bytes calldata selectorData,
                bytes32 digest
            ) = _enableValidatorDigest(ValidatorLib.getValidator(vId), selector, packedData);
            bytes calldata enableSig;
            assembly {
                enableSig.offset := add(add(packedData.offset, 32), calldataload(add(packedData.offset, 132)))
                enableSig.length := calldataload(sub(enableSig.offset, 32))
            }
            _installValidator(vId, config, validatorData, hookData);
            if(selectorData.length >= 4) {
                require(bytes4(selectorData[0:4]) == selector);
                if(selectorData.length >= 44) {
                    _installSelector(selector, config.group, address(bytes20(selectorData[4:24])), IHook(address(bytes20(selectorData[24:44]))), selectorData[44:]);
                } else {
                    _installSelector(selector, config.group, address(0), IHook(address(0)), selectorData[0:0]);
                }
            } else {
                require(selectorData.length == 0);
            }
            bytes4 result = _validateSignature(rootValidator, address(this), digest, enableSig);
            if (result != 0x1626ba7e) {
                revert InvalidSignature();
            }
        }
    }

    function _enableValidatorDigest(IValidator validator, bytes4 selector, bytes calldata packedData)
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
            validatorData.offset := add(add(packedData.offset, 32), calldataload(add(packedData.offset, 36)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            hookData.offset := add(add(packedData.offset, 32), calldataload(add(packedData.offset, 68)))
            hookData.length := calldataload(sub(hookData.offset, 32))
            selectorData.offset := add(add(packedData.offset, 32), calldataload(add(packedData.offset, 100)))
            selectorData.length := calldataload(sub(selectorData.offset, 32))
        }
        digest = _hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "Enable(address validator,uint32 nonce,bytes4 group,uint48 validFrom,uint48 validUntil,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                    ), // TODO: this to constant
                    validator,
                    currentNonce,
                    config.group,
                    selector,
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

    function _validateSignature(ValidatorIdentifier validator, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (bytes4 result)
    {
        if (ValidatorLib.getType(validator) == TYPE_VALIDATOR) {
            result = ValidatorLib.getValidator(validator).isValidSignatureWithSender(caller, digest, sig);
        } else if (ValidatorLib.getType(validator) == TYPE_PERMISSION) {
            revert("NOT_IMPLEMENTED_SIGNATURE_VALIDATION");
        } else {
            revert InvalidValidator();
        }
    }
}
