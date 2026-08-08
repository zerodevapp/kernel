// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IValidator, IPolicy, ISigner, IScopedExecutionHook} from "../interfaces/IERC7579Modules.sol";
import {
    InvalidRootValidation,
    ModuleInstallFailed,
    OccupiedValidationId,
    InvalidPermissionUninstallOrder,
    ScopedExecutionHookStillInstalled,
    ScopedExecutionHookAlreadyInstalled,
    InvalidScopedExecutionHookTarget,
    InvalidPermissionId,
    InvalidSelectorGrant,
    InvalidValidationType,
    CannotUninstallRoot,
    InvalidVid,
    InvalidDataLength,
    InvalidPermissionInstall,
    InvalidSignature
} from "../types/Error.sol";
import {ValidationId, PermissionId, ValidationType} from "../types/Types.sol";
import {
    VALIDATION_MANAGER_STORAGE_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    VALIDATION_TYPE_FALLBACK,
    ERC1271_MAGICVALUE,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    SCOPED_EXECUTION_HOOK_NOT_INSTALLED
} from "../types/Constants.sol";
import {PermissionSignature, ValidationStorage, ValidationInfo, Install} from "../types/Structs.sol";
import {Lib4337} from "../lib/Lib4337.sol";
import {
    getType,
    getValidator,
    getPermissionId,
    validatorToIdentifier,
    permissionToIdentifier,
    validationScopedExecutionHookId
} from "../lib/Utils.sol";

/// @title ValidationManager
/// @author taek <leekt216@gmail.com>
/// @notice Manages validation identifiers (validators and permissions), root validation, and signature verification.
abstract contract ValidationManager {
    bytes32 private constant _SCOPED_EXECUTION_HOOK_ADDRESS_KEY = keccak256("kernel.scopedExecutionHook.address");
    bytes32 private constant _SCOPED_EXECUTION_HOOK_VALIDATION_ID_KEY =
        keccak256("kernel.scopedExecutionHook.validationId");

    /// @dev Tracks the permission being installed within a batch to ensure consistency.
    ValidationId transient installingPermission;

    /// @notice Returns the current root validation identifier.
    /// @return The root ValidationId.
    function root() external view returns (ValidationId) {
        ValidationStorage storage $ = _validationStorage();
        return $.root;
    }

    /// @notice Retrieves the validation ID and scoped execution hook stored for a userOp hash.
    function _validationScopedExecutionHook(bytes32 userOpHash)
        internal
        view
        returns (ValidationId vId, IScopedExecutionHook hook)
    {
        bytes32 hookKey = keccak256(abi.encodePacked(_SCOPED_EXECUTION_HOOK_ADDRESS_KEY, userOpHash));
        bytes32 vIdKey = keccak256(abi.encodePacked(_SCOPED_EXECUTION_HOOK_VALIDATION_ID_KEY, userOpHash));
        assembly {
            hook := tload(hookKey)
            vId := tload(vIdKey)
        }
    }

    /// @notice Stores a validation ID and scoped execution hook keyed by the userOp hash.
    function _setValidationScopedExecutionHook(bytes32 userOpHash, ValidationId vId, IScopedExecutionHook hook)
        internal
    {
        bytes32 hookKey = keccak256(abi.encodePacked(_SCOPED_EXECUTION_HOOK_ADDRESS_KEY, userOpHash));
        bytes32 vIdKey = keccak256(abi.encodePacked(_SCOPED_EXECUTION_HOOK_VALIDATION_ID_KEY, userOpHash));
        assembly {
            tstore(hookKey, hook)
            tstore(vIdKey, vId)
        }
    }

    /// @notice Returns the scoped identifier exposed to a validation-scoped execution hook.
    function _validationScopedExecutionHookId(ValidationId vId) internal pure returns (bytes32) {
        return validationScopedExecutionHookId(vId);
    }

    /// @notice Returns the validation info (hook, signer, policies) for a given ValidationId.
    /// @param vId The validation identifier to query.
    /// @return The ValidationInfo struct for this identifier.
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
    /// @dev Defense-in-depth: non-root validations are forbidden from being granted
    ///      `IAccountExecute.executeUserOp.selector`. The `_processUserOp` fast-path bypasses
    ///      the inner-selector check and the validation hook setup when the outer call's
    ///      selector is itself in the allow-list AND no hook is installed -- so allowing a
    ///      non-root validation to allow-list `executeUserOp` would let it invoke ANY
    ///      kernel function via `executeUserOp`'s inner delegatecall with no selector check.
    ///      Root is exempt because it is the unconditional last-resort access path and is
    ///      already intentionally exempt from selector allow-listing.
    function _grantAccess(ValidationId vId, bytes calldata selectors) internal {
        require(selectors.length % 4 == 0, InvalidDataLength());
        ValidationStorage storage $ = _validationStorage();
        uint32 nonce = ++$.vInfo[vId].nonce;

        while (selectors.length >= 4) {
            bytes4 selector = bytes4(selectors[0:4]);
            require(selector != IAccountExecute.executeUserOp.selector || vId == $.root, InvalidSelectorGrant());
            $.allowed[vId][selector] = nonce;
            selectors = selectors[4:];
        }
    }

    /// @dev Returns whether the selector allowance nonce matches the validation's current nonce.
    function _allowedSelector(ValidationId vId, bytes4 selector) internal view returns (bool) {
        ValidationStorage storage $ = _validationStorage();
        return $.allowed[vId][selector] == $.vInfo[vId].nonce;
    }

    /// @notice Marks a validation as installed and initializes its allowed selectors.
    function _initializeValidation(ValidationId vId, bytes calldata selectors) internal {
        ValidationInfo storage info = _validationStorage().vInfo[vId];
        require(!info.installed, OccupiedValidationId());
        info.installed = true;
        if (selectors.length == 0) {
            // Invalidate selector grants from any prior installation of this ValidationId.
            ++info.nonce;
        } else {
            _grantAccess(vId, selectors);
        }
    }

    /// @notice Installs a validator module and initializes its validation storage.
    /// @param _validator The validator module address.
    /// @param _internalData Packed bytes4 selectors.
    /// @param _installSuccess Whether the module's onInstall call succeeded.
    function _installValidator(address _validator, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        // Defense-in-depth: require the validator to have code at install time so a
        // codeless address (whose `staticcall` returns success with empty returndata)
        // cannot be installed as a validator and then later authorise arbitrary signatures.
        require(_validator.code.length > 0, ModuleInstallFailed());
        ValidationId vId = validatorToIdentifier(IValidator(_validator));
        _initializeValidation(vId, _internalData);
    }

    /// @notice Installs a policy module for a permission-based validation.
    /// @dev The first 4 bytes of _internalData must be the PermissionId.
    /// @param _policy The policy module address.
    /// @param _internalData PermissionId (4 bytes) prepended to policy-specific data.
    /// @param _installSuccess Whether the module's onInstall call succeeded.
    function _installPolicy(address _policy, bytes calldata _internalData, bool _installSuccess) internal {
        ValidationInfo storage $ = _checkPermissionInstall(_internalData, _installSuccess);
        require(_internalData.length >= 4, InvalidDataLength());
        $.policies.push(_policy);
    }

    /// @notice Installs a signer module for a permission-based validation.
    /// @dev Must be installed after all policies for the same PermissionId. Finalizes the permission by
    ///      initializing validation and resetting the transient installingPermission.
    /// @param _signer The signer module address.
    /// @param _internalData PermissionId (4 bytes) followed by packed bytes4 selectors.
    /// @param _installSuccess Whether the module's onInstall call succeeded.
    function _installSigner(address _signer, bytes calldata _internalData, bool _installSuccess) internal {
        ValidationInfo storage $ = _checkPermissionInstall(_internalData, _installSuccess);
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        $.signer = _signer;
        _initializeValidation(vId, _internalData[4:]);
        installingPermission = ValidationId.wrap(bytes21(0));
    }

    /// @notice Installs a scoped execution hook for an existing validator or permission.
    function _installValidationScopedExecutionHook(address _hook, ValidationId vId, bool _installSuccess) internal {
        require(_installSuccess && _hook.code.length > 0, ModuleInstallFailed());
        ValidationInfo storage info = _validationStorage().vInfo[vId];
        require(info.installed, InvalidScopedExecutionHookTarget());
        if (getType(vId) == VALIDATION_TYPE_PERMISSION) {
            require(info.signer != address(0), InvalidScopedExecutionHookTarget());
        }
        require(
            address(info.scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
            ScopedExecutionHookAlreadyInstalled()
        );
        info.scopedExecutionHook = IScopedExecutionHook(_hook);
    }

    /// @notice Validates that a permission install is consistent (same PermissionId within a batch).
    /// @param _internalData Data with PermissionId in the first 4 bytes.
    /// @param _installSuccess Whether the module's onInstall call succeeded.
    /// @return $ The ValidationInfo storage reference for the permission.
    function _checkPermissionInstall(bytes calldata _internalData, bool _installSuccess)
        internal
        returns (ValidationInfo storage $)
    {
        require(_internalData.length >= 4, InvalidDataLength());
        require(_installSuccess, ModuleInstallFailed());
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        $ = _validationStorage().vInfo[vId];
        if (installingPermission == ValidationId.wrap(bytes21(0))) {
            require(vId != ValidationId.wrap(bytes21(0)), InvalidPermissionInstall());
            installingPermission = vId;
        } else {
            require(installingPermission == vId, InvalidPermissionInstall());
        }
    }

    /// @notice Marks a validation as uninstalled. Cannot uninstall root.
    /// @param _vId The validation identifier to uninstall.
    function _uninstallValidation(ValidationId _vId) internal {
        ValidationStorage storage $ = _validationStorage();
        require($.root != _vId, CannotUninstallRoot());
        require(
            address($.vInfo[_vId].scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
            ScopedExecutionHookStillInstalled()
        );
        $.vInfo[_vId].installed = false;
    }

    /// @notice Uninstalls a validator module.
    /// @param _validator The validator module address.
    function _uninstallValidator(address _validator, bytes calldata, bool) internal {
        ValidationId vId = validatorToIdentifier(IValidator(_validator));
        _uninstallValidation(vId);
    }

    /// @notice Uninstalls a scoped execution hook without uninstalling its validator or permission.
    function _uninstallScopedExecutionHookWithVid(address _hook, ValidationId vId) internal {
        ValidationInfo storage info = _validationStorage().vInfo[vId];
        require(address(info.scopedExecutionHook) == _hook, InvalidScopedExecutionHookTarget());
        info.scopedExecutionHook = IScopedExecutionHook(SCOPED_EXECUTION_HOOK_NOT_INSTALLED);
    }

    /// @notice Uninstalls a policy module. Policies must be uninstalled in reverse order (LIFO).
    /// @param _policy The policy module address.
    /// @param _internalData Data with PermissionId in the first 4 bytes.
    function _uninstallPolicy(address _policy, bytes calldata _internalData, bool) internal {
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        _uninstallPolicyWithVid(_policy, vId);
    }

    /// @notice Removes a policy from a validation's policy array (must be the last element).
    /// @param _policy The policy address to remove.
    /// @param vId The validation identifier the policy belongs to.
    function _uninstallPolicyWithVid(address _policy, ValidationId vId) internal {
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        unchecked {
            require($.policies[$.policies.length - 1] == _policy, InvalidPermissionUninstallOrder());
            $.policies.pop();
        }
    }

    /// @notice Uninstalls a signer module. All policies must be uninstalled first.
    /// @param _signer The signer module address.
    /// @param _internalData Data with PermissionId in the first 4 bytes.
    function _uninstallSigner(address _signer, bytes calldata _internalData, bool) internal {
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(bytes4(_internalData[0:4])));
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        require($.policies.length == 0, InvalidPermissionUninstallOrder());
        _uninstallSignerWithVid(_signer, vId);
    }

    /// @notice Removes a signer from a validation and marks the validation as uninstalled.
    /// @param _signer The signer address to remove.
    /// @param vId The validation identifier the signer belongs to.
    function _uninstallSignerWithVid(address _signer, ValidationId vId) internal {
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        require(
            address($.scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED, ScopedExecutionHookStillInstalled()
        );
        require($.policies.length == 0, InvalidPermissionUninstallOrder());
        require($.signer == _signer, InvalidPermissionId());
        $.signer = address(0);
        _uninstallValidation(vId);
    }

    /// @notice Resolves the validation function based on type. For root type, follows through to the stored root.
    /// @param vType The validation type from the nonce.
    /// @param vId The validation identifier from the nonce.
    /// @return v The resolved ValidationId (may differ from vId if root type).
    /// @return validateUserOp The validation function pointer to call.
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
        require(info.installed, InvalidVid(v));

        if (vType == VALIDATION_TYPE_PERMISSION) {
            validateUserOp = _validateUserOpPermission;
        } else {
            validateUserOp = _validateUserOpValidator;
        }
    }

    /// @notice Verifies a signature against a validation identifier (validator or permission).
    /// @param vId The validation identifier; bytes21(0) falls through to fallback signer.
    /// @param requester The address requesting signature verification (passed to modules).
    /// @param _hash The hash that was signed.
    /// @param _signature The signature bytes.
    /// @return validationData Packed validation result (0 = success, 1 = failure).
    function _verifySignature(ValidationId vId, address requester, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (uint256 validationData)
    {
        if (ValidationId.unwrap(vId) == bytes21(0)) {
            return
                _verifyFallbackSignature(_hash, _signature) ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
        }
        ValidationInfo storage vInfo = _validationStorage().vInfo[vId];
        require(vInfo.installed, InvalidVid(vId));
        ValidationType vType = getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = getValidator(vId);
            validationData = validator.isValidSignatureWithSender(requester, _hash, _signature) == ERC1271_MAGICVALUE
                ? SIG_VALIDATION_SUCCESS_UINT
                : SIG_VALIDATION_FAILED_UINT;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            return _verifySignaturePermission(vId, vInfo, requester, _hash, _signature);
        } else {
            return SIG_VALIDATION_FAILED_UINT;
        }
    }

    /// @notice Verifies a permission-based signature by checking all policies and the signer.
    /// @param vId The permission ValidationId.
    /// @param vInfo The validation info containing policies and signer.
    /// @param requester The address requesting verification.
    /// @param _hash The hash that was signed.
    /// @param _signature Encoded as PermissionSignature (array of signatures for each policy + signer).
    /// @return validationData Intersected validation result from all policies and the signer.
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
            require(permissionSig.signatures.length == vInfo.policies.length + 1, InvalidSignature());
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
                    ? SIG_VALIDATION_SUCCESS_UINT
                    : SIG_VALIDATION_FAILED_UINT
            );
        }
    }

    /// @notice Validates a userOp using the fallback signer (e.g., EOA for 7702/immutable ECDSA).
    function _validateUserOpFallback(
        ValidationId,
        bytes32 opHash,
        PackedUserOperation memory,
        bytes calldata userOpSignature
    ) internal virtual returns (uint256 validationData) {
        return _verifyFallbackSignature(opHash, userOpSignature)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    /// @notice Validates a userOp using an installed IValidator module.
    /// @dev Uses a direct interface call so that validator revert reasons propagate to the caller.
    function _validateUserOpValidator(
        ValidationId vId,
        bytes32 opHash,
        PackedUserOperation memory op,
        bytes calldata userOpSignature
    ) internal returns (uint256 validationData) {
        IValidator validator = getValidator(vId);
        op.signature = userOpSignature;
        (bool success, bytes memory ret) =
            address(validator).call(abi.encodeCall(IValidator.validateUserOp, (op, opHash)));
        // Require a properly-encoded `uint256` (32 bytes) return. A codeless / non-conforming
        // validator returns success with empty returndata, which would otherwise decode to 0
        // (SIG_VALIDATION_SUCCESS) and authorise any signature.
        validationData = (success && ret.length == 32) ? abi.decode(ret, (uint256)) : SIG_VALIDATION_FAILED_UINT;
    }

    /// @notice Validates a userOp using a permission (policies + signer).
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
            require(permissionSig.signatures.length == vInfo.policies.length + 1, InvalidSignature());
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

    /// @notice Default fallback signature verification; always returns false unless overridden.
    function _verifyFallbackSignature(bytes32, bytes calldata) internal view virtual returns (bool) {
        return false;
    }

    /// @notice Sets the root validation from an Install package (validator, policy, or signer type).
    /// @param pkg The install package whose module becomes the root.
    function _setRoot(Install calldata pkg) internal {
        ValidationId vId;
        if (pkg.moduleType == MODULE_TYPE_VALIDATOR) {
            vId = validatorToIdentifier(IValidator(pkg.module));
        } else if (pkg.moduleType == MODULE_TYPE_POLICY || pkg.moduleType == MODULE_TYPE_SIGNER) {
            vId = permissionToIdentifier(PermissionId.wrap(bytes4(pkg.internalData[0:4])));
        } else {
            revert InvalidRootValidation();
        }
        _setRoot(vId);
    }

    /// @notice Returns whether a fallback validator is available. Override in 7702/immutable ECDSA variants.
    function _fallbackValidatorAvailable() internal pure virtual returns (bool) {
        return false;
    }

    /// @notice Sets the root validation to the given ValidationId directly.
    /// @dev Validates that the id is a valid type and that the validation is installed.
    ///      On rotation (oldRoot != newRoot, oldRoot non-zero) the old root's nonce is
    ///      bumped to invalidate any `allowed[oldRoot][*]` selector grants accumulated
    ///      while it was root. Without this, after rotation the old root becomes a
    ///      non-root validation whose prior grants -- including potentially
    ///      `executeUserOp.selector` -- remain active and re-enable the `_processUserOp`
    ///      fast-path bypass that commit 0921b25 fixed on the grant side. This is the
    ///      rotation-boundary defense-in-depth counterpart to that fix.
    /// @param vId The validation identifier to set as root.
    function _setRoot(ValidationId vId) internal {
        // Check for zero ValidationId first (before type check to get correct error)
        require(ValidationId.unwrap(vId) != bytes21(0) || _fallbackValidatorAvailable(), InvalidRootValidation());
        ValidationType vType = getType(vId);
        require(
            vType == VALIDATION_TYPE_VALIDATOR || vType == VALIDATION_TYPE_PERMISSION
                || (_fallbackValidatorAvailable() && vType == VALIDATION_TYPE_FALLBACK),
            InvalidValidationType()
        );
        ValidationStorage storage $ = _validationStorage();
        // Require the validation to actually be installed before promoting it to root.
        // The fallback path (vId == bytes21(0)) is exempt since it has no install step.
        if (ValidationId.unwrap(vId) != bytes21(0)) {
            require($.vInfo[vId].installed, InvalidVid(vId));
        }
        // Invalidate stale grants on the previous root when rotating. The first install
        // (oldRoot zero) and identity rotation (oldRoot == newRoot) are no-ops.
        ValidationId oldRoot = $.root;
        if (ValidationId.unwrap(oldRoot) != bytes21(0) && oldRoot != vId) {
            ++$.vInfo[oldRoot].nonce;
        }
        $.root = vId;
    }
}
