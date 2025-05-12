pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import "../interfaces/IERC7579Modules.sol";
import "../types/Error.sol";
import "../types/Types.sol";
import "../types/Constants.sol";

struct ValidationInfo {
    bool enabled;
    bytes4 group;
}

struct ValidationGroupInfo {
    mapping(bytes4 selector => bool) allowed;
    bytes32 permission;
}

struct ValidationStorage {
    ValidationId rootValidator;
    mapping(IValidator validator => ValidationInfo) vInfo;
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

contract ValidationManager {
    function _validationStorage() internal view returns (ValidationStorage storage $) {
        assembly {
            $.slot := VALIDATION_MANAGER_STORAGE_SLOT
        }
    }

    function _installValidatorHook(address _validator, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[IValidator(_validator)].enabled = true;
    }

    function _uninstallValidatorHook(address _validator, bytes calldata _internalData, bool _uninstallSuccess)
        internal
    {
        require(_uninstallSuccess, ModuleUninstallFailed());
        ValidationStorage storage $ = _validationStorage();
        $.vInfo[IValidator(_validator)].enabled = false;
    }

    function _checkValidation(ValidationMode vMode, ValidationType vType, ValidationId vId) internal view {
        ValidationStorage storage $ = _validationStorage();
        ValidationId v;
        if (vType == VALIDATION_TYPE_ROOT) {
            v = $.rootValidator;
        } else {
            v = vId;
            require($.vInfo[IValidator(getValidator(v))].enabled, InvalidValidator());
        }
        // TODO : add permission support
    }

    function _parseNonce(uint256 nonce)
        internal
        pure
        returns (ValidationMode vMode, ValidationType vType, ValidationId vId)
    {
        // 2bytes mode (1byte currentMode, 1byte type)
        // 20bytes identifier
        // 1byte mode  | 1byte type | 20bytes vId | 2byte nonceKey | 8byte nonce == 32bytes
        assembly {
            vMode := nonce
            vType := shl(8, nonce)
            vId := shl(16, nonce)
        }
    }

    function _verifySignature(ValidationId vId, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (uint256 validationData)
    {
        IValidator validator = IValidator(getValidator(vId)); // TODO: add permission support;
        validator.isValidSignatureWithSender(address(0), /*NOTE: fix this */ _hash, _signature);
    }
}
