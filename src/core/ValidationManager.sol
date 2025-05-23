pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import "../interfaces/IERC7579Modules.sol";
import "../types/Error.sol";
import "../types/Types.sol";
import "../types/Constants.sol";
import "../types/Structs.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

struct ValidationInfo {
    ValidationType vType;
    address[] policies;
    address signer;
    bytes4 group;
}

struct ValidationGroupInfo {
    mapping(bytes4 selector => bool) allowed;
    bytes32 permission;
}

struct ValidationStorage {
    ValidationId root;
    mapping(ValidationId vId => ValidationInfo) vInfo;
    mapping(bytes4 group => ValidationGroupInfo) gInfo;
}

function getValidator(ValidationId vId) pure returns (address v) {
    assembly {
        v := shr(96, vId)
    }
}

function getType(ValidationId validator) pure returns (ValidationType vType) {
    assembly {
        vType := validator
    }
}

function parseNonce(uint256 nonce) pure returns (ValidationMode vMode, ValidationType vType, ValidationId vId) {
    // 2bytes mode (1byte currentMode, 1byte type)
    // 20bytes identifier
    // 1byte mode  | 1byte type | 20bytes vId | 2byte nonceKey | 8byte nonce == 32bytes
    assembly {
        vMode := nonce
        vType := shl(8, nonce)
        vId := shl(16, nonce)
    }
}

abstract contract ValidationManager {
    ValidationId transient installingPermission;

    function _validationStorage() internal view returns (ValidationStorage storage $) {
        assembly {
            $.slot := VALIDATION_MANAGER_STORAGE_SLOT
        }
    }

    function _installValidator(address _validator, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[ValidationId.wrap(bytes20(_validator))].vType = VALIDATION_TYPE_VALIDATOR;
    }

    function _uninstallValidator(address _validator, bytes calldata _internalData, bool _uninstallSuccess) internal {
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[ValidationId.wrap(bytes20(_validator))].vType = VALIDATION_TYPE_ROOT;
    }

    function _installPolicy(address _policy, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        if (installingPermission == ValidationId.wrap(bytes20(0))) {
            require(vId != ValidationId.wrap(bytes20(0)), "invalid validationId");
            installingPermission = ValidationId.wrap(bytes20(_internalData[0:20]));
            $.vInfo[vId].vType = VALIDATION_TYPE_PERMISSION;
        } else {
            require(installingPermission == vId, "permissionId should be consistent");
        }
        $.vInfo[vId].policies.push(_policy);
    }

    function _uninstallPolicy(address _policy, bytes calldata _internalData, bool _uninstallSuccess) internal {}

    function _installSigner(address _signer, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        if (installingPermission == ValidationId.wrap(bytes20(0))) {
            require(vId != ValidationId.wrap(bytes20(0)), "invalid validationId");
            require($.vInfo[vId].vType == ValidationType.wrap(0x00), "already taken");
            installingPermission = ValidationId.wrap(bytes20(_internalData[0:20]));
            $.vInfo[vId].vType = VALIDATION_TYPE_PERMISSION;
        } else {
            require(installingPermission == vId, "permissionId should be consistent");
        }
        $.vInfo[vId].signer = _signer;

        installingPermission = ValidationId.wrap(bytes20(0));
    }

    function _uninstallSigner(address _signer, bytes calldata _internalData, bool _uninstallSuccess) internal {}

    function _checkValidation(ValidationMode vMode, ValidationType vType, ValidationId vId) internal view returns(ValidationId v) {
        ValidationStorage storage $ = _validationStorage();
        if (vType == VALIDATION_TYPE_ROOT) {
            v = $.root;
        } else {
            v = vId;
            require($.vInfo[vId].vType == vType, InvalidValidator());
        }
    }

    function _verifySignature(ValidationId vId, address requester, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (uint256 validationData)
    {
        if (ValidationId.unwrap(vId) == bytes20(0)) {
            return _verify7702Signature(_hash, _signature) ? 0 : 1;
        }
        IValidator validator = IValidator(getValidator(vId)); // TODO: add permission support;
        validator.isValidSignatureWithSender(requester, /*NOTE: fix this */ _hash, _signature);
    }

    function _validateUserOp(
        ValidationId vId,
        bytes32 opHash,
        PackedUserOperation calldata op,
        bytes calldata userOpSignature
    ) internal returns (uint256 validationData) {
        if (ValidationId.unwrap(vId) == bytes20(0)) {
            return _verify7702Signature(opHash, userOpSignature) ? 0 : 1;
        }
        // NOTE: removed permission for now, adding back after testing is done
        address validator = address(ValidationId.unwrap(vId));
        PackedUserOperation memory modifiedOp = op;
        modifiedOp.signature = userOpSignature;
        return IValidator(validator).validateUserOp(modifiedOp, opHash);
    }

    function _verify7702Signature(bytes32 hash, bytes calldata sig) internal view returns (bool) {
        return ECDSA.recover(hash, sig) == address(this);
    }

    function _setRoot(Install calldata pkg) internal {
        ValidationId vId;
        if (pkg.moduleType == 1) {
            vId = ValidationId.wrap(bytes20(pkg.module));
        } else if (pkg.moduleType == 5 || pkg.moduleType == 6) {
            vId = ValidationId.wrap(bytes20(pkg.internalData[0:4]));
        } else {
            revert InvalidRootValidation();
        }
        _setRoot(vId);
    }

    function _setRoot(ValidationId vId) internal {
        ValidationStorage storage $ = _validationStorage();
        $.root = vId;
    }
}
