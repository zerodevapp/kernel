pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, IPolicy, ISigner, IHook} from "../interfaces/IERC7579Modules.sol";
import {InvalidRootValidation, ModuleInstallFailed, OccupiedValidationId, ModuleInstallFailed, InvalidPermissionUninstallOrder, InvalidPermissionUninstallOrder, InvalidPermissionId, InvalidValidator} from "../types/Error.sol";
import {ValidationId, ValidationType, ValidationMode} from "../types/Types.sol";
import {VALIDATION_MANAGER_STORAGE_SLOT, VALIDATION_TYPE_ROOT,VALIDATION_TYPE_VALIDATOR,VALIDATION_TYPE_PERMISSION,ERC1271_MAGICVALUE} from "../types/Constants.sol";
import {ValidationStorage, ValidationInfo, Install} from "../types/Structs.sol";
import {Lib4337} from "../lib/Lib4337.sol";

function parseNonce(uint256 nonce) pure returns (ValidationMode vMode, ValidationType vType, ValidationId vId) {
    // 2bytes mode (1byte currentMode, 1byte type)
    // 20bytes identifier
    // 1byte mode | 1byte type | 20bytes vId | 2byte nonceKey | 8byte nonce == 32bytes
    vMode = ValidationMode.wrap(bytes1(bytes32(nonce)));
    vType = ValidationType.wrap(bytes1(bytes32(nonce << 8)));
    vId = ValidationId.wrap(bytes20(bytes32(nonce << 16)));
}

abstract contract ValidationManager {
    ValidationId transient installingPermission;
    IHook transient validationHook;

    function root() external view returns (ValidationId) {
        ValidationStorage storage $ = _validationStorage();
        return $.root;
    }

    function validationInfo(ValidationId vId) external view returns (ValidationInfo memory) {
        ValidationStorage storage $ = _validationStorage();
        return $.vInfo[vId];
    }

    function _validationStorage() internal pure returns (ValidationStorage storage $) {
        assembly {
            $.slot := VALIDATION_MANAGER_STORAGE_SLOT
        }
    }

    function _initializeValidation(ValidationId vId, bytes calldata _internalData) internal {
        ValidationStorage storage $ = _validationStorage();

        // if _internalData is empty, skip the initialization
        if (_internalData.length == 0) {
            return;
        }
        // if not, first 20 bytes is the hook address
        address hook = address(bytes20(_internalData[0:20]));
        $.vInfo[vId].hook = hook;
        _internalData = _internalData[20:];

        // then the rest is the allowed selectors
        while (_internalData.length >= 4) {
            bytes4 selector = bytes4(_internalData[0:4]);
            $.allowed[vId][selector] = true;
            _internalData = _internalData[4:];
        }
    }

    function _installValidator(address _validator, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = ValidationId.wrap(bytes20(_validator));
        require($.vInfo[vId].vType == VALIDATION_TYPE_ROOT, OccupiedValidationId());
        $.vInfo[vId].vType = VALIDATION_TYPE_VALIDATOR;
        _initializeValidation(vId, _internalData);
    }

    function _installPolicy(address _policy, bytes calldata _internalData, bool _installSuccess) internal {
        ValidationInfo storage $ = _checkPermissionInstall(_internalData, _installSuccess);
        $.policies.push(_policy);
    }

    function _installSigner(address _signer, bytes calldata _internalData, bool _installSuccess) internal {
        ValidationInfo storage $ = _checkPermissionInstall(_internalData, _installSuccess);
        $.signer = _signer;
        installingPermission = ValidationId.wrap(bytes20(0));
    }

    function _checkPermissionInstall(bytes calldata _internalData, bool _installSuccess)
        internal
        returns (ValidationInfo storage $)
    {
        require(_installSuccess, ModuleInstallFailed());
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        $ = _validationStorage().vInfo[vId];
        if (installingPermission == ValidationId.wrap(bytes20(0))) {
            require(vId != ValidationId.wrap(bytes20(0)), "invalid validationId");
            require($.vType == ValidationType.wrap(0x00), "already taken");
            installingPermission = vId;
            $.vType = VALIDATION_TYPE_PERMISSION;
            _initializeValidation(vId, _internalData[20:]);
        } else {
            require(installingPermission == vId, "permissionId should be consistent");
        }
    }

    function _uninstallValidator(address _validator, bytes calldata _internalData, bool _uninstallSuccess) internal {
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = ValidationId.wrap(bytes20(_validator));
        $.vInfo[vId].vType = VALIDATION_TYPE_ROOT;
    }

    function _uninstallPolicy(address _policy, bytes calldata _internalData, bool _uninstallSuccess) internal {
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        $ = _validationStorage().vInfo[vId];
        unchecked {
            require($.policies[$.policies.length - 1] == _policy, InvalidPermissionUninstallOrder());
            $.policies.pop();
        }
        if ($.signer == address(0)) {
            $.vType = VALIDATION_TYPE_ROOT;
        }
    }

    function _uninstallSigner(address _signer, bytes calldata _internalData, bool _uninstallSuccess) internal {
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        require($.policies.length == 0, InvalidPermissionUninstallOrder());
        require($.signer == _signer, InvalidPermissionId());
        $.signer = address(0);
        $.vType = VALIDATION_TYPE_ROOT;
    }

    function _checkValidation(ValidationType vType, ValidationId vId)
        internal
        view
        returns (
            ValidationId v,
            function(ValidationId, bytes32, PackedUserOperation memory, bytes calldata) internal returns(uint256) validateUserOp
        )
    {
        ValidationStorage storage $ = _validationStorage();
        if (vType == VALIDATION_TYPE_ROOT || $.vInfo[vId].vType == VALIDATION_TYPE_ROOT) {
            v = $.root;
            if (ValidationId.unwrap(v) == bytes20(0)) {
                return (v, _validateUserOpFallback);
            }
            vType = $.vInfo[v].vType;
        } else {
            v = vId;
            require($.vInfo[vId].vType == vType, InvalidValidator());
        }

        if (vType == VALIDATION_TYPE_PERMISSION) {
            validateUserOp = _validateUserOpPermission;
        } else {
            validateUserOp = _validateUserOpValidator;
        }
    }

    function _verifySignature(ValidationId vId, address requester, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (uint256 validationData)
    {
        if (ValidationId.unwrap(vId) == bytes20(0)) {
            return _verifyFallbackSignature(_hash, _signature) ? 0 : 1;
        }
        ValidationInfo storage vInfo = _validationStorage().vInfo[vId];
        if (vInfo.vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = IValidator(address(ValidationId.unwrap(vId))); // TODO: add permission support;
            validationData = validator.isValidSignatureWithSender(requester, /*NOTE: fix this */ _hash, _signature)
                == ERC1271_MAGICVALUE ? 0 : 1;
        } else if (vInfo.vType == VALIDATION_TYPE_PERMISSION) {
            return _verifySignaturePermission(vId, vInfo, requester, _hash, _signature);
        } else {
            return 1;
        }
    }

    function _verifySignaturePermission(
        ValidationId vId,
        ValidationInfo storage vInfo,
        address requester,
        bytes32 _hash,
        bytes calldata _signature
    ) internal view returns (uint256 validationData) {
        unchecked {
            PermissionSignature calldata permissionSig;
            assembly {
                permissionSig := _signature.offset
            }
            bytes32 paddedVId = bytes32(ValidationId.unwrap(vId));
            for (uint256 i = 0; i < vInfo.policies.length; i++) {
                IPolicy policy = IPolicy(vInfo.policies[i]);
                validationData = Lib4337.intersectValidationData(
                    validationData,
                    policy.checkSignaturePolicy(paddedVId, requester, _hash, permissionSig.signatures[i])
                );
            }
            validationData = Lib4337.intersectValidationData(
                validationData,
                ISigner(vInfo.signer).checkSignature(
                    paddedVId, requester, _hash, permissionSig.signatures[permissionSig.signatures.length - 1]
                ) == ERC1271_MAGICVALUE ? 0 : 1
            );
        }
    }

    function _validateUserOpFallback(
        ValidationId,
        bytes32 opHash,
        PackedUserOperation memory,
        bytes calldata userOpSignature
    ) internal virtual returns (uint256 validationData) {
        return _verifyFallbackSignature(opHash, userOpSignature) ? 0 : 1;
    }

    function _validateUserOpValidator(
        ValidationId vId,
        bytes32 opHash,
        PackedUserOperation memory op,
        bytes calldata userOpSignature
    ) internal returns (uint256 validationData) {
        // NOTE: removed permission for now, adding back after testing is done
        address validator = address(ValidationId.unwrap(vId));
        op.signature = userOpSignature;
        return IValidator(validator).validateUserOp(op, opHash);
    }

    struct PermissionSignature {
        bytes[] signatures;
    }

    function _validateUserOpPermission(
        ValidationId vId,
        bytes32 opHash,
        PackedUserOperation memory op,
        bytes calldata userOpSignature
    ) internal returns (uint256 validationData) {
        ValidationInfo storage vInfo = _validationStorage().vInfo[vId];
        unchecked {
            PermissionSignature calldata permissionSig;
            assembly {
                permissionSig := userOpSignature.offset
            }
            bytes32 paddedVId = bytes32(ValidationId.unwrap(vId));
            for (uint256 i = 0; i < vInfo.policies.length; i++) {
                IPolicy policy = IPolicy(vInfo.policies[i]);
                op.signature = permissionSig.signatures[i];
                validationData =
                    Lib4337.intersectValidationData(validationData, policy.checkUserOpPolicy(paddedVId, op));
            }

            op.signature = permissionSig.signatures[permissionSig.signatures.length - 1];
            return Lib4337.intersectValidationData(
                validationData, ISigner(vInfo.signer).checkUserOpSignature(paddedVId, op, opHash)
            );
        }
    }

    function _verifyFallbackSignature(bytes32, bytes calldata) internal view virtual returns (bool) {
        return false;
    }

    function _setRoot(Install calldata pkg) internal {
        ValidationId vId;
        if (pkg.moduleType == 1) {
            vId = ValidationId.wrap(bytes20(pkg.module));
        } else if (pkg.moduleType == 5 || pkg.moduleType == 6) {
            vId = ValidationId.wrap(bytes20(pkg.internalData[0:20]));
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
