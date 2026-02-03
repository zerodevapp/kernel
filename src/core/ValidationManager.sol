pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, IPolicy, ISigner, IHook} from "../interfaces/IERC7579Modules.sol";
import {
    InvalidRootValidation,
    ModuleInstallFailed,
    OccupiedValidationId,
    ModuleInstallFailed,
    InvalidPermissionUninstallOrder,
    InvalidPermissionId,
    CannotUninstallRoot,
    InvalidVid,
    InvalidDataLength,
    NotInstalled
} from "../types/Error.sol";
import {ValidationId, PermissionId, ValidationType} from "../types/Types.sol";
import {
    VALIDATION_MANAGER_STORAGE_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    ERC1271_MAGICVALUE
} from "../types/Constants.sol";
import {PermissionSignature, ValidationStorage, ValidationInfo, Install} from "../types/Structs.sol";
import {Lib4337} from "../lib/Lib4337.sol";
import {getType, getValidator, getPermissionId, validatorToIdentifier, permissionToIdentifier} from "../lib/Utils.sol";

abstract contract ValidationManager {
    ValidationId transient installingPermission;

    function _hookEnabled(IHook _hook) internal view virtual returns (bool);

    function root() external view returns (ValidationId) {
        ValidationStorage storage $ = _validationStorage();
        return $.root;
    }

    function _validationHook(bytes32 userOpHash) internal view returns (IHook hook) {
        assembly {
            hook := tload(userOpHash)
        }
    }

    function _setValidationHook(bytes32 userOpHash, IHook hook) internal {
        assembly {
            tstore(userOpHash, hook)
        }
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

    /// @dev grant access to selectors
    /// @param vId validationId
    /// @param selectors = abi.encodePacked(bytes4 selectors)
    function _grantAccess(ValidationId vId, bytes calldata selectors) internal {
        require(selectors.length % 4 == 0, InvalidDataLength());
        ValidationStorage storage $ = _validationStorage();
        uint32 nonce = ++$.vInfo[vId].nonce;

        while (selectors.length >= 4) {
            bytes4 selector = bytes4(selectors[0:4]);
            $.allowed[vId][selector] = nonce;
            selectors = selectors[4:];
        }
    }

    /// @dev returns bool if nonce matches the selector allowance, you should also check hook to make sure validation is installed
    function _allowedSelector(ValidationId vId, bytes4 selector) internal view returns (bool) {
        ValidationStorage storage $ = _validationStorage();
        return $.allowed[vId][selector] == $.vInfo[vId].nonce;
    }

    function _initializeValidation(ValidationId vId, bytes calldata _internalData) internal {
        ValidationStorage storage $ = _validationStorage();
        require($.vInfo[vId].hook == address(0), OccupiedValidationId());
        // if _internalData is empty, skip the initialization
        if (_internalData.length == 0) {
            $.vInfo[vId].hook = address(1);
            return;
        }
        // if not, first 20 bytes is the hook address
        address hook = address(bytes20(_internalData[0:20]));
        require(hook == address(0) || hook == address(1) || _hookEnabled(IHook(hook)), NotInstalled());
        $.vInfo[vId].hook = hook == address(0) ? address(1) : hook;
        _internalData = _internalData[20:];
        // then the rest is the allowed selectors
        _grantAccess(vId, _internalData);
    }

    function _installValidator(address _validator, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = validatorToIdentifier(IValidator(_validator));
        _initializeValidation(vId, _internalData);
    }

    function _installPolicy(address _policy, bytes calldata _internalData, bool _installSuccess) internal {
        ValidationInfo storage $ = _checkPermissionInstall(_internalData, _installSuccess);
        require(_internalData.length == 4, InvalidDataLength());
        $.policies.push(_policy);
    }

    function _installSigner(address _signer, bytes calldata _internalData, bool _installSuccess) internal {
        ValidationInfo storage $ = _checkPermissionInstall(_internalData, _installSuccess);
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        $.signer = _signer;
        _initializeValidation(vId, _internalData[4:]);
        installingPermission = ValidationId.wrap(bytes21(0));
    }

    function _checkPermissionInstall(bytes calldata _internalData, bool _installSuccess)
        internal
        returns (ValidationInfo storage $)
    {
        require(_installSuccess, ModuleInstallFailed());
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        $ = _validationStorage().vInfo[vId];
        if (installingPermission == ValidationId.wrap(bytes21(0))) {
            require(vId != ValidationId.wrap(bytes21(0)), "invalid validationId");
            installingPermission = vId;
            // _initializeValidation(vId, _internalData[4:]);
        } else {
            require(installingPermission == vId, "permissionId should be consistent");
        }
    }

    function _uninstallValidation(ValidationId _vId) internal {
        ValidationStorage storage $ = _validationStorage();
        require($.root != _vId, CannotUninstallRoot());
        $.vInfo[_vId].hook = address(0);
    }

    function _uninstallValidator(address _validator, bytes calldata, bool) internal {
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = validatorToIdentifier(IValidator(_validator));
        _uninstallValidation(vId);
    }

    function _uninstallPolicy(address _policy, bytes calldata _internalData, bool) internal {
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        _uninstallPolicyWithVid(_policy, vId);
    }

    function _uninstallPolicyWithVid(address _policy, ValidationId vId) internal {
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        unchecked {
            require($.policies[$.policies.length - 1] == _policy, InvalidPermissionUninstallOrder());
            $.policies.pop();
        }
    }

    function _uninstallSigner(address _signer, bytes calldata _internalData, bool) internal {
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        require($.policies.length == 0, InvalidPermissionUninstallOrder());
        _uninstallSignerWithVid(_signer, vId);
    }

    function _uninstallSignerWithVid(address _signer, ValidationId vId) internal {
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        require($.policies.length == 0, InvalidPermissionUninstallOrder());
        require($.signer == _signer, InvalidPermissionId());
        $.signer = address(0);
        _uninstallValidation(vId);
    }

    function _checkValidation(ValidationType vType, ValidationId vId)
        internal
        view
        returns (
            ValidationId v,
            function(ValidationId, bytes32, PackedUserOperation memory, bytes calldata)
                internal returns (uint256) validateUserOp
        )
    {
        ValidationStorage storage $ = _validationStorage();
        if (vType == VALIDATION_TYPE_ROOT) {
            v = $.root;
            if (ValidationId.unwrap(v) == bytes21(0)) {
                return (v, _validateUserOpFallback);
            }
            vType = getType(v);
        } else {
            v = vId;
        }

        ValidationInfo storage info = _validationStorage().vInfo[v];
        require(info.hook > address(0), InvalidVid(v));

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
        if (ValidationId.unwrap(vId) == bytes21(0)) {
            return _verifyFallbackSignature(_hash, _signature) ? 0 : 1;
        }
        ValidationInfo storage vInfo = _validationStorage().vInfo[vId];
        require(vInfo.hook > address(0), InvalidVid(vId));
        ValidationType vType = getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = getValidator(vId);
            validationData =
                validator.isValidSignatureWithSender(requester, _hash, _signature) == ERC1271_MAGICVALUE ? 0 : 1;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
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
            bytes32 paddedVId = bytes32(PermissionId.unwrap(getPermissionId(vId)));
            for (uint256 i = 0; i < vInfo.policies.length; i++) {
                IPolicy policy = IPolicy(vInfo.policies[i]);
                validationData = Lib4337.intersectValidationData(
                    validationData,
                    policy.checkSignaturePolicy(paddedVId, requester, _hash, permissionSig.signatures[i])
                );
            }
            validationData = Lib4337.intersectValidationData(
                validationData,
                ISigner(vInfo.signer)
                    .checkSignature(
                        paddedVId, requester, _hash, permissionSig.signatures[permissionSig.signatures.length - 1]
                    ) == ERC1271_MAGICVALUE
                    ? 0
                    : 1
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
        IValidator validator = getValidator(vId);
        op.signature = userOpSignature;
        //return validator.validateUserOp(op, opHash);
        (bool success, bytes memory ret) =
            address(validator).call(abi.encodeCall(IValidator.validateUserOp, (op, opHash)));
        //validationData = success ? abi.decode(ret, (uint256)) : 1;
        // forge-lint: disable-next-line(unsafe-typecast)
        validationData = success ? uint256(bytes32(ret)) : 1;
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
            bytes32 paddedVId = bytes32(PermissionId.unwrap(getPermissionId(vId)));
            for (uint256 i = 0; i < vInfo.policies.length; ++i) {
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
            vId = validatorToIdentifier(IValidator(address(bytes20(pkg.module))));
        } else if (pkg.moduleType == 5 || pkg.moduleType == 6) {
            vId = permissionToIdentifier(PermissionId.wrap(bytes4(pkg.internalData[0:4])));
        } else {
            revert InvalidRootValidation();
        }
        _setRoot(vId);
    }

    function _fallbackValidatorAvailable() internal pure virtual returns (bool) {
        return false;
    }

    function _setRoot(ValidationId vId) internal {
        require(ValidationId.unwrap(vId) != bytes21(0) || _fallbackValidatorAvailable(), InvalidRootValidation());
        ValidationStorage storage $ = _validationStorage();
        $.root = vId;
    }
}
