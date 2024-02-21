pragma solidity ^0.8.0;

import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {ValidationData} from "../interfaces/IAccount.sol";
import {EIP712} from "solady/utils/EIP712.sol";

type Validator is bytes22;

type ValidatorMode is bytes1;

ValidatorMode constant MODE_DEFAULT = ValidatorMode.wrap(0x00);
ValidatorMode constant MODE_ENABLE = ValidatorMode.wrap(0x01);
ValidatorType constant TYPE_SUDO = ValidatorType.wrap(0x00);
ValidatorType constant TYPE_VALIDATOR = ValidatorType.wrap(0x01);
ValidatorType constant TYPE_PERMISSION = ValidatorType.wrap(0x02);

using {vModeEqual as ==} for ValidatorMode global;
using {vTypeEqual as ==} for ValidatorType global;
using {vModeNotEqual as !=} for ValidatorMode global;
using {vTypeNotEqual as !=} for ValidatorType global;

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

function validatorToIdentifier(Validator validator) pure returns (ValidatorIdentifier vId) {
    // TODO: add test to check if this works properly
    assembly {
        vId := shr(8, validator)
    }
}

function getType(ValidatorIdentifier validator) pure returns (ValidatorType vType) {
    assembly {
        vType := validator
    }
}

function getValidator(ValidatorIdentifier validator) pure returns (IValidator v) {
    assembly {
        v := shl(8, validator)
    }
}

type ValidatorIdentifier is bytes21;

type ValidatorType is bytes1;

type PermissionData is bytes22;

function getPermissionValidator(PermissionData data) pure returns (IValidator vId) {
    assembly {
        vId := data
    }
}

library ValidatorLib {
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
}

abstract contract ValidationManager is EIP712 {
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
    mapping(ValidatorIdentifier validator => IValidator[]) public permissionConfig;

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
        bytes4[] calldata groups,
        IHook[] calldata hooks,
        uint48[] calldata validFrom,
        uint48[] calldata validUntil,
        bytes[] calldata validatorData,
        bytes[] calldata hookData
    ) internal {
        // onlyEntrypointOrSelf
        uint32 nonce = currentNonce;
        for (uint256 i = 0; i < validators.length; i++) {
            _installValidator(
                validators[i], nonce, groups[i], validFrom[i], validUntil[i], hooks[i], validatorData[i], hookData[i]
            );
        }
        currentNonce++;
    }

    function _installValidator(
        ValidatorIdentifier validator,
        uint32 nonce,
        bytes4 group,
        uint48 validFrom,
        uint48 validUntil,
        IHook hook,
        bytes calldata data,
        bytes calldata hookData
    ) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        validatorConfig[validator] =
            ValidatorConfig({nonce: nonce, validFrom: validFrom, validUntil: validUntil, group: group, hook: hook});
        ValidatorType vType = getType(validator);
        if (vType == TYPE_VALIDATOR) {
            IValidator(getValidator(validator)).onInstall(data);
        } else if (vType == TYPE_PERMISSION) {
            //TODO
        } else {
            revert InvalidValidator();
        }
        if (address(hook) != address(1)) {
            hook.onInstall(hookData);
        }
    }

    function _doValidation(
        ValidatorMode vMode,
        ValidatorType vType,
        ValidatorIdentifier vId,
        PackedUserOperation calldata op,
        bytes32 userOpHash
    ) internal returns (ValidationData validationData) {
        ValidatorIdentifier validator = vId;
        PackedUserOperation memory userOp = op;
        if (vType == TYPE_SUDO) {
            validator = rootValidator; // change to validator when root since root does not have any vId in userOp.signature
        }
        if (vMode == MODE_ENABLE) {
            bytes calldata userOpSig = _enableMode(validator, op.signature);
            userOp.signature = userOpSig;
            currentNonce++;
        }
        if (getType(validator) == TYPE_VALIDATOR) {
            validationData = ValidationData.wrap(getValidator(validator).validateUserOp(userOp, userOpHash));
        } else if (getType(validator) == TYPE_PERMISSION) {
            // TODO
        } else {
            revert InvalidValidator();
        }
    }

    function _enableMode(ValidatorIdentifier vId, bytes calldata signature)
        internal
        returns (bytes calldata userOpSig)
    {
        if (getType(vId) == TYPE_VALIDATOR) {
            userOpSig = _doEnableValidator(vId, signature);
        } else {
            revert("");
        }
        return userOpSig;
    }

    function _doEnableValidator(ValidatorIdentifier vId, bytes calldata signature)
        internal
        returns (bytes calldata userOpSig)
    {
        bytes4 group;
        uint48 validFrom;
        uint48 validUntil;
        IHook hook;
        bytes calldata validatorData;
        bytes calldata hookData;
        bytes calldata enableSig;

        group = bytes4(signature[0:4]);
        validFrom = uint48(bytes6(signature[4:10]));
        validUntil = uint48(bytes6(signature[10:16]));
        hook = IHook(address(bytes20(signature[16:36])));
        assembly {
            validatorData.offset := add(add(signature.offset, 32), calldataload(add(signature.offset, 36)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            hookData.offset := add(add(signature.offset, 32), calldataload(add(signature.offset, 68)))
            hookData.length := calldataload(sub(hookData.offset, 32))
            enableSig.offset := add(add(signature.offset, 32), calldataload(add(signature.offset, 100)))
            enableSig.length := calldataload(sub(enableSig.offset, 32))
        }

        _checkEnableValidatorSig(
            vId, currentNonce, group, validFrom, validUntil, hook, validatorData, hookData, enableSig
        );
        _installValidator(vId, currentNonce, group, validFrom, validUntil, hook, validatorData, hookData);
        assembly {
            userOpSig.offset := add(add(signature.offset, 32), calldataload(add(signature.offset, 132)))
            userOpSig.length := calldataload(sub(userOpSig.offset, 32))
        }
    }

    function _checkEnableValidatorSig(
        ValidatorIdentifier validator,
        uint32 nonce,
        bytes4 group,
        uint48 validFrom,
        uint48 validUntil,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData,
        bytes calldata enableSig
    ) internal view {
        if (getType(validator) != TYPE_VALIDATOR) {
            revert InvalidValidator();
        }
        bytes32 digest = _hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "Enable(bytes21 validator,uint32 nonce,bytes4 group,uint48 validFrom,uint48 validUntil,address hook,bytes validatorData,bytes hookData)"
                    ), // TODO: this to constant
                    validator,
                    nonce,
                    group,
                    validFrom,
                    validUntil,
                    hook,
                    keccak256(validatorData),
                    keccak256(hookData)
                )
            )
        );
        bytes4 result = _validateSignature(rootValidator, address(this), digest, enableSig);
        if (result != 0x1626ba7e) {
            revert InvalidSignature();
        }
    }

    function _validateSignature(ValidatorIdentifier validator, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (bytes4 result)
    {
        if (getType(validator) == TYPE_VALIDATOR) {
            result = getValidator(validator).isValidSignatureWithSender(caller, digest, sig);
        } else if (getType(validator) == TYPE_PERMISSION) {
            // TODO
        } else {
            revert InvalidValidator();
        }
    }
}
