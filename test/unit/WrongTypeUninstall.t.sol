// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {ModuleNotInstalled, InvalidVid} from "src/types/Error.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, MODULE_TYPE_FALLBACK} from "src/types/Constants.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {CALLTYPE_SINGLE} from "src/types/Constants.sol";

/// @notice TOB-KERNEL-12 regression: uninstalling a module under a type it is not installed as
///         must revert BEFORE the module receives an onUninstall callback. Otherwise an authority
///         limited to uninstallModule can fire wrong-type onUninstall at, e.g., the root validator
///         and wipe its state without changing the root ValidationId (bricking the account).
contract WrongTypeUninstallTest is Test {
    IEntryPoint ep;
    Kernel kernel;
    MockValidator validator;
    MockExecutor executor;
    MockFallback fallbackModule;

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);
        address eoa = makeAddr("Owner");
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));

        validator = new MockValidator();
        validator.sudoSetSuccess(true);
        executor = new MockExecutor();
        fallbackModule = new MockFallback();

        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encode(hex"", hex""));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));
        kernel.installModule(
            MODULE_TYPE_FALLBACK,
            address(fallbackModule),
            abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector, CALLTYPE_SINGLE))
        );
        vm.stopPrank();
    }

    function test_InstalledValidatorCannotBeUninstalledAsExecutor() external {
        vm.prank(address(ep));
        vm.expectRevert(ModuleNotInstalled.selector);
        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(validator), abi.encode(hex"", hex""));

        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""),
            "validator must stay installed and receive no wrong-type callback"
        );
    }

    function test_NeverInstalledValidatorCannotBeUninstalled() external {
        MockValidator stranger = new MockValidator();
        vm.prank(address(ep));
        vm.expectRevert(
            abi.encodeWithSelector(InvalidVid.selector, validatorToIdentifier(IValidator(address(stranger))))
        );
        kernel.uninstallModule(MODULE_TYPE_VALIDATOR, address(stranger), abi.encode(hex"", hex""));
    }

    function test_FallbackUninstallRequiresMatchingModule() external {
        vm.prank(address(ep));
        vm.expectRevert(ModuleNotInstalled.selector);
        kernel.uninstallModule(
            MODULE_TYPE_FALLBACK,
            address(validator), // wrong module for this selector
            abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector))
        );

        assertTrue(
            kernel.isModuleInstalled(
                MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(MockFallback.fallbackFunction.selector)
            ),
            "fallback must stay installed"
        );
    }

    /// @dev Positive controls: correctly-typed uninstalls still work after the checks.
    function test_CorrectTypeUninstallsStillWork() external {
        vm.startPrank(address(ep));
        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));
        kernel.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encode(hex"", hex""));
        kernel.uninstallModule(
            MODULE_TYPE_FALLBACK,
            address(fallbackModule),
            abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""));
        assertFalse(
            kernel.isModuleInstalled(
                MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(MockFallback.fallbackFunction.selector)
            )
        );
    }
}
