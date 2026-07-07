pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, ValidationInfo, SelectorConfig, ExecutorConfig} from "src/types/Structs.sol";
import {ValidationId, CallType, PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {CALLTYPE_SINGLE, HOOK_MODULE_NOT_INSTALLED, HOOK_MODULE_INSTALLED_NO_HOOK} from "src/types/Constants.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IHook} from "src/interfaces/IERC7579Modules.sol";

/// @title KernelModuleIdempotencyHalmos
/// @notice Halmos proofs that install+uninstall is idempotent for all module types
contract KernelModuleIdempotencyHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
    }

    /// @notice Prove validator install+uninstall returns to not-installed state
    function check_ValidatorInstallUninstallIdempotent() external {
        MockValidator v = new MockValidator();
        assertFalse(kernel.isModuleInstalled(1, address(v), hex""));

        vm.startPrank(address(ep));
        kernel.installModule(1, address(v), abi.encode(hex"deadbeef", hex""));
        assertTrue(kernel.isModuleInstalled(1, address(v), hex""));

        kernel.uninstallModule(1, address(v), abi.encode(hex"", hex""));
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(1, address(v), hex""));
    }

    /// @notice Prove executor install+uninstall returns to not-installed state
    function check_ExecutorInstallUninstallIdempotent() external {
        MockExecutor e = new MockExecutor();
        assertFalse(kernel.isModuleInstalled(2, address(e), hex""));

        vm.startPrank(address(ep));
        kernel.installModule(2, address(e), abi.encode(hex"deadbeef", hex""));
        assertTrue(kernel.isModuleInstalled(2, address(e), hex""));

        kernel.uninstallModule(2, address(e), abi.encode(hex"", hex""));
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(2, address(e), hex""));
        ExecutorConfig memory cfg = kernel.executorConfig(address(e));
        assertEq(address(cfg.hook), HOOK_MODULE_NOT_INSTALLED);
    }

    /// @notice Prove selector install+uninstall returns to not-installed state
    function check_SelectorInstallUninstallIdempotent() external {
        MockFallback f = new MockFallback();
        MockHook h = new MockHook();
        bytes4 selector = MockFallback.testFunction.selector;

        vm.startPrank(address(ep));
        kernel.installModule(4, address(h), abi.encode(hex"", hex""));
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        kernel.installModule(3, address(f), abi.encode(hex"deadbeef", abi.encodePacked(selector, callType, address(h))));
        assertTrue(kernel.isModuleInstalled(3, address(f), abi.encodePacked(selector)));

        kernel.uninstallModule(3, address(f), abi.encode(hex"", abi.encodePacked(selector)));
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(3, address(f), abi.encodePacked(selector)));
        SelectorConfig memory cfg = kernel.selectorConfig(selector);
        assertEq(cfg.target, address(0));
        assertEq(CallType.unwrap(cfg.callType), bytes1(0));
    }

    /// @notice Prove hook install+uninstall returns to not-installed state
    function check_HookInstallUninstallIdempotent() external {
        MockHook h = new MockHook();
        assertFalse(kernel.isModuleInstalled(4, address(h), hex""));

        vm.startPrank(address(ep));
        kernel.installModule(4, address(h), abi.encode(hex"", hex""));
        assertTrue(kernel.isModuleInstalled(4, address(h), hex""));

        kernel.uninstallModule(4, address(h), abi.encode(hex"", hex""));
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(4, address(h), hex""));
    }

    /// @notice Prove permission (policy+signer) install+uninstall returns to not-installed state
    function check_PermissionInstallUninstallIdempotent() external {
        MockPolicy p = new MockPolicy();
        MockSigner s = new MockSigner();
        bytes4 permId = bytes4(keccak256("test_perm"));
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(permId));

        vm.startPrank(address(ep));
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: 5, module: address(p), moduleData: hex"deadbeef", internalData: abi.encodePacked(permId)
        });
        pkgs[1] = Install({
            moduleType: 6, module: address(s), moduleData: hex"deadbeef", internalData: abi.encodePacked(permId)
        });
        kernel.installModule(pkgs);

        assertTrue(kernel.isModuleInstalled(5, address(p), abi.encodePacked(permId)));
        assertTrue(kernel.isModuleInstalled(6, address(s), abi.encodePacked(permId)));

        // Uninstall in reverse order: policy first, then signer
        kernel.uninstallModule(5, address(p), abi.encode(hex"", abi.encodePacked(permId)));
        kernel.uninstallModule(6, address(s), abi.encode(hex"", abi.encodePacked(permId)));
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(5, address(p), abi.encodePacked(permId)));
        assertFalse(kernel.isModuleInstalled(6, address(s), abi.encodePacked(permId)));

        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertEq(vInfo.hook, HOOK_MODULE_NOT_INSTALLED);
        assertEq(vInfo.signer, address(0));
        assertEq(vInfo.policies.length, 0);
    }

    /// @notice Prove that installing the same validator twice reverts with OccupiedValidationId
    function check_ValidatorDoubleInstallReverts() external {
        MockValidator v = new MockValidator();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(v), abi.encode(hex"", hex""));

        try kernel.installModule(1, address(v), abi.encode(hex"", hex"")) {
            assert(false); // should not succeed
        } catch {}
        vm.stopPrank();
    }
}
