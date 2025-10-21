pragma solidity ^0.8.0;

import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockHook} from "./mock/MockHook.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {NotImplemented} from "src/types/Error.sol";
import {Install} from "src/types/Structs.sol";
import {ERC1967_IMPLEMENTATION_SLOT} from "src/types/Constants.sol";
import {KernelUserOpTest} from "./KernelUserOpTest.sol";
import {KernelERC1271Test} from "./KernelERC1271Test.sol";
import {KernelExecutorTest} from "./KernelExecutorTest.sol";
import {KernelValidatorTest} from "./KernelValidatorTest.sol";
import {KernelExecuteTest} from "./KernelExecuteTest.sol";
import {KernelSelectorTest} from "./KernelSelectorTest.sol";
import {KernelHookTest} from "./KernelHookTest.sol";
import {PermissionId} from "src/types/Types.sol";

contract KernelTest is
    KernelUserOpTest,
    KernelERC1271Test,
    KernelExecutorTest,
    KernelValidatorTest,
    KernelExecuteTest,
    KernelSelectorTest,
    KernelHookTest
{
    KernelUUPS uups;

    function setUp() external {
        ep = EntryPointLib.deploy();

        uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        newValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        policy = new MockPolicy();
        signer = new MockSigner();
        hook = new MockHook();
        permissionId = PermissionId.wrap(bytes4(keccak256(abi.encodePacked("Hello world"))));
        _initialize();
    }

    function test_implementation_revert_on_initialize() external {
        rootValidator = new MockValidator();
        rootValidatorData = hex"";
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        vm.expectRevert();
        uups.initialize(pkgs);
    }

    function _initialize() internal virtual override {
        isMock = true;
        rootValidator = new MockValidator();
        rootValidatorData = hex"";
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", ""));
        vm.stopPrank();
    }

    function test_install_packages_with_signature() external unitTest {
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));
        vm.snapshotGasLastCall("Install - 3");
    }

    function test_install_packages_with_signature_replayable() external unitTest {
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        kernel.installModule(true, 0, packages, enableSig(0, true, true, packages, _rootSignHash));
    }

    function test_upgradeTo() external unitTest {
        vm.skip(is7702);
        KernelUUPS newTemplate = new KernelUUPS(ep);
        KernelUUPS(payable(address(kernel))).upgradeToAndCall(address(newTemplate), hex"");
        bytes32 impl = vm.load(address(kernel), ERC1967_IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(impl))), address(newTemplate));
    }

    function test_install_invalid() external unitTest {
        vm.expectRevert(NotImplemented.selector);
        kernel.installModule(10, address(hook), abi.encode(hex"", ""));
        vm.expectRevert(NotImplemented.selector);
        kernel.isModuleInstalled(10, address(hook), abi.encodePacked(permissionId));
    }

    function test_uninstall_invalid() external unitTest {
        vm.expectRevert(NotImplemented.selector);
        kernel.uninstallModule(10, address(hook), abi.encode(hex"", ""));
    }

    function test_supports_module() external unitTest {
        assertFalse(kernel.supportsModule(0));
        assertTrue(kernel.supportsModule(1));
        assertTrue(kernel.supportsModule(2));
        assertTrue(kernel.supportsModule(3));
        assertTrue(kernel.supportsModule(4));
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        assertFalse(kernel.supportsModule(7));
    }
}
