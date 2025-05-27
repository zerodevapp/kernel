pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import "../interfaces/IERC7579Modules.sol";
import "../types/Error.sol";
import "../types/Types.sol";
import "../types/Constants.sol";
import "../types/Structs.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import "forge-std/console.sol";
import {Lib4337} from "../lib/Lib4337.sol";

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

    function validationInfo(ValidationId vId) external view returns(ValidationInfo memory) {
        ValidationStorage storage $ = _validationStorage();
        return $.vInfo[vId];
    }

    function _validationStorage() internal view returns (ValidationStorage storage $) {
        assembly {
            $.slot := VALIDATION_MANAGER_STORAGE_SLOT
        }
    }

    function _installValidator(address _validator, bytes calldata _internalData, bool _installSuccess) internal {
        require(_installSuccess, ModuleInstallFailed());
        ValidationStorage storage $ = _validationStorage();
        ValidationId vId = ValidationId.wrap(bytes20(_validator));
        require($.vInfo[vId].vType == VALIDATION_TYPE_ROOT, OccupiedValidationId());
        $.vInfo[vId].vType = VALIDATION_TYPE_VALIDATOR;
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

    function _checkPermissionInstall(bytes calldata _internalData, bool _installSuccess) internal returns(ValidationInfo storage $) {
        require(_installSuccess, ModuleInstallFailed());
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        $ = _validationStorage().vInfo[vId];
        if (installingPermission == ValidationId.wrap(bytes20(0))) {
            require(vId != ValidationId.wrap(bytes20(0)), "invalid validationId");
            require($.vType == ValidationType.wrap(0x00), "already taken");
            installingPermission = vId;
            $.vType = VALIDATION_TYPE_PERMISSION;
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
        require($.policies[$.policies.length - 1] == _policy, InvalidPermissionUninstallOrder());
        $.policies.pop();
    }

    function _uninstallSigner(address _signer, bytes calldata _internalData, bool _uninstallSuccess) internal {
        ValidationId vId = ValidationId.wrap(bytes20(_internalData[0:20]));
        ValidationInfo storage $ = _validationStorage().vInfo[vId];
        require($.policies.length == 0, InvalidPermissionUninstallOrder());
        require($.signer == _signer, InvalidPermissionId());
        $.signer = address(0);
        $.vType = VALIDATION_TYPE_ROOT;
    }

    function _checkValidation(ValidationMode vMode, ValidationType vType, ValidationId vId)
        internal
        view
        returns (
            ValidationId v,
            function(ValidationId, bytes32, PackedUserOperation calldata, bytes calldata) internal returns(uint256)
            validateUserOp
        )
    {
        ValidationStorage storage $ = _validationStorage();
        if (vType == VALIDATION_TYPE_ROOT || $.vInfo[vId].vType == VALIDATION_TYPE_ROOT) {
            v = $.root;
            vType = $.vInfo[v].vType;
        } else {
            v = vId;
            require($.vInfo[vId].vType == vType, InvalidValidator());
        }

        if (vType == VALIDATION_TYPE_VALIDATOR) {
            validateUserOp = _validateUserOpValidator;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            validateUserOp = _validateUserOpPermission;
        } else {
            revert InvalidValidationType();
        }
    }

    function _verifySignature(ValidationId vId, address requester, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (bytes4)
    {
        if (ValidationId.unwrap(vId) == bytes20(0)) {
            return _verify7702Signature(_hash, _signature) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
        }
        IValidator validator = IValidator(getValidator(vId)); // TODO: add permission support;
        return validator.isValidSignatureWithSender(requester, /*NOTE: fix this */ _hash, _signature);
    }

    function _validateUserOpValidator(
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

    struct PermissionSignature {
        bytes[] signatures;
    }

    function _validateUserOpPermission(
        ValidationId vId,
        bytes32 opHash,
        PackedUserOperation calldata op,
        bytes calldata userOpSignature
    ) internal returns (uint256 validationData) {
        ValidationInfo storage vInfo = _validationStorage().vInfo[vId];
        unchecked {
        uint256 length = vInfo.policies.length + 1;

        PermissionSignature calldata permissionSig;
        assembly {
            permissionSig := userOpSignature.offset
        }
        PackedUserOperation memory modifiedOp = op;
        bytes32 paddedVId = bytes32(ValidationId.unwrap(vId));
        for (uint256 i = 0; i < vInfo.policies.length; i++) {
            IPolicy policy = IPolicy(vInfo.policies[i]);
            modifiedOp.signature = permissionSig.signatures[i];
            validationData = _intersectValidationData(validationData, policy.checkUserOpPolicy(paddedVId, modifiedOp));
        }

        modifiedOp.signature = permissionSig.signatures[permissionSig.signatures.length - 1];
        return _intersectValidationData(validationData, ISigner(vInfo.signer).checkUserOpSignature(paddedVId, modifiedOp, opHash));
        }
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

    function _intersectValidationData(uint256 a, uint256 b) internal pure returns (uint256 validationData) {
        assembly {
            // xor(a,b) == shows only matching bits
            // and(xor(a,b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff) == filters out the validAfter and validUntil bits
            // if the result is not zero, then aggregator part is not matching
            // validCase :
            // a == 0 || b == 0 || xor(a,b) == 0
            // invalidCase :
            // a mul b != 0 && xor(a,b) != 0
            let sum := shl(96, add(a, b))
            switch or(
                iszero(and(xor(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)),
                or(eq(sum, shl(96, a)), eq(sum, shl(96, b)))
            )
            case 1 {
                validationData := and(or(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)
                // validAfter
                let a_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, a)
                let b_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, b)
                validationData := or(validationData, xor(a_vd, mul(xor(a_vd, b_vd), gt(b_vd, a_vd))))
                // validUntil
                a_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, a)
                if iszero(a_vd) { a_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
                b_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, b)
                if iszero(b_vd) { b_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
                let until := xor(a_vd, mul(xor(a_vd, b_vd), lt(b_vd, a_vd)))
                if iszero(until) { until := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
                validationData := or(validationData, until)
            }
            default { validationData := SIG_VALIDATION_FAILED_UINT }
        }
    }
}
