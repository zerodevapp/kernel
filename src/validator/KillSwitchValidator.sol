// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "solady/utils/ECDSA.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/core/Helpers.sol";
import "src/Kernel.sol";
import {WalletKernelStorage, ExecutionDetail} from "src/abstract/KernelStorage.sol";
import "src/interfaces/IValidator.sol";

struct KillSwitchValidatorStorage {
    address guardian;
    IKernelValidator validator;
    uint48 pausedUntil;
    bytes4 disableMode;
}

contract KillSwitchValidator is IKernelValidator {
    mapping(address => KillSwitchValidatorStorage) public killSwitchValidatorStorage;

    function enable(bytes calldata enableData) external payable override {
        killSwitchValidatorStorage[msg.sender].guardian = address(bytes20(enableData[0:20]));
    }

    function disable(bytes calldata) external payable override {
        delete killSwitchValidatorStorage[msg.sender];
    }

    function validateSignature(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[msg.sender];
        uint256 res = validatorStorage.validator.validateSignature(hash, signature);
        uint48 pausedUntil = validatorStorage.pausedUntil;
        ValidationData memory validationData = _parseValidationData(res);
        if (validationData.aggregator != address(1)) {
            // if signature verification has not been failed, return with the result
            uint256 delayedData = _packValidationData(false, 0, pausedUntil);
            return _packValidationData(_intersectTimeRange(res, delayedData));
        }
        return SIG_VALIDATION_FAILED;
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (uint256)
    {
        KillSwitchValidatorStorage storage validatorStorage = killSwitchValidatorStorage[msg.sender]; // should use msg.sender to prevent others from changing storage
        uint48 pausedUntil = validatorStorage.pausedUntil;
        uint256 validationResult = 0;
        if (address(validatorStorage.validator) != address(0)) {
            // check for validator at first
            try validatorStorage.validator.validateUserOp(_userOp, _userOpHash, pausedUntil) returns (uint256 res) {
                validationResult = res;
            } catch {
                validationResult = SIG_VALIDATION_FAILED;
            }
            ValidationData memory validationData = _parseValidationData(validationResult);
            if (validationData.aggregator != address(1)) {
                // if signature verification has not been failed, return with the result
                uint256 delayedData = _packValidationData(false, 0, pausedUntil);
                return _packValidationData(_intersectTimeRange(validationResult, delayedData));
            }
        }
        if (_userOp.signature.length == 71) {
            // save data to this storage
            validatorStorage.pausedUntil = uint48(bytes6(_userOp.signature[0:6]));
            validatorStorage.validator = KernelStorage(msg.sender).getDefaultValidator();
            validatorStorage.disableMode = KernelStorage(msg.sender).getDisabledMode();
            bytes32 hash = ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(_userOp.signature[0:6], _userOpHash)));
            address recovered = ECDSA.recover(hash, _userOp.signature[6:]);
            if (validatorStorage.guardian != recovered) {
                return SIG_VALIDATION_FAILED;
            }
            return _packValidationData(false, 0, pausedUntil);
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert("not implemented");
    }
}
