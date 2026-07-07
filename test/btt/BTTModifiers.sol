// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {KernelTestBase} from "../KernelTestBase.sol";

/// @title BTT Shared Modifiers
/// @notice Common modifiers used across BTT test contracts
/// @dev Inherit from this contract instead of defining modifiers in each BTT test
abstract contract BTTModifiers is KernelTestBase {
    /*//////////////////////////////////////////////////////////////
                        STATE VARIABLES FOR BTT BRANCH TRACKING
    //////////////////////////////////////////////////////////////*/

    // Validation type tracking
    uint8 internal _validationType; // 0 = root, 1 = validator, 2 = permission

    // Validation mode tracking
    bool internal _enableFlagSet;
    bool internal _enableSignatureValid;
    bool internal _replayableMode;

    // Module state tracking
    bool internal _validatorInstalled;
    bool internal _permissionInstalled;

    // Module type tracking
    uint256 internal _moduleTypeId;

    // Note: _callType and _execType are defined locally in test files that need them
    // to avoid conflicts with file-specific modifiers (e.g., Kernel.execute.t.sol)

    // Signature format tracking
    bool internal _isERC7739MagicHash;
    bool internal _isEnableMode;
    bool internal _isTypedDataSign;

    /*//////////////////////////////////////////////////////////////
                        CALLER MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Sets caller to a random address (not EntryPoint)
    modifier whenCallerIsNotEntryPoint() virtual {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        _;
    }

    /// @dev Sets caller to a different random address (not account itself)
    modifier whenCallerIsNotAccountItself() virtual {
        vm.stopPrank();
        vm.startPrank(makeAddr("notAccountItself"));
        _;
    }

    /// @dev Sets caller to EntryPoint
    modifier whenCallerIsEntryPointOrSelf() virtual {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    VALIDATION TYPE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenValidationTypeIsRoot() virtual {
        _validationType = 0;
        _;
    }

    modifier givenValidationTypeIsValidator() virtual {
        _validationType = 1;
        _;
    }

    modifier givenValidationTypeIsPermission() virtual {
        _validationType = 2;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    VALIDATION MODE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenValidationModeHasEnableFlagSet() virtual {
        _enableFlagSet = true;
        _;
    }

    modifier givenEnableSignatureIsInvalid() virtual {
        _enableSignatureValid = false;
        _;
    }

    modifier givenEnableSignatureIsValidAndNonceUnused() virtual {
        _enableSignatureValid = true;
        _;
    }

    modifier givenValidationModeIsReplayable() virtual {
        _replayableMode = true;
        _;
    }

    modifier givenValidationModeIsNotReplayable() virtual {
        _replayableMode = false;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    MODULE STATE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenValidatorIsNotInstalled() virtual {
        _validatorInstalled = false;
        _;
    }

    modifier givenValidatorIsInstalled() virtual {
        _validatorInstalled = true;
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        _;
    }

    modifier givenPermissionIsNotInstalled() virtual {
        _permissionInstalled = false;
        _;
    }

    modifier givenPermissionIsInstalled() virtual {
        _permissionInstalled = true;
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    EXECUTION MODE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    // Note: Execution mode modifiers (_callType, _execType) are defined locally
    // in test files that need them (e.g., Kernel.execute.t.sol) because they
    // have file-specific helper functions that use these variables.

    /*//////////////////////////////////////////////////////////////
                    MODULE TYPE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenModuleTypeIsValidator() virtual {
        _moduleTypeId = 1;
        _;
    }

    modifier givenModuleTypeIsExecutor() virtual {
        _moduleTypeId = 2;
        _;
    }

    modifier givenModuleTypeIsFallback() virtual {
        _moduleTypeId = 3;
        _;
    }

    modifier givenModuleTypeIsHook() virtual {
        _moduleTypeId = 4;
        _;
    }

    modifier givenModuleTypeIsPolicy() virtual {
        _moduleTypeId = 5;
        _;
    }

    modifier givenModuleTypeIsSigner() virtual {
        _moduleTypeId = 6;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    SIGNATURE FORMAT MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenHashIsERC7739MagicHash() virtual {
        _isERC7739MagicHash = true;
        _;
    }

    modifier givenHashIsNotERC7739MagicHash() virtual {
        _isERC7739MagicHash = false;
        _;
    }

    modifier givenSignatureModeIndicatesEnableMode() virtual {
        _isEnableMode = true;
        _;
    }

    modifier givenSignatureFormatIsTypedDataSign() virtual {
        _isTypedDataSign = true;
        _;
    }

    modifier givenSignatureFormatIsPersonalSign() virtual {
        _isTypedDataSign = false;
        _;
    }
}
