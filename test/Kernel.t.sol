pragma solidity ^0.8.0;

import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelHelper} from "src/KernelHelper.sol";
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

contract KernelTest is
    KernelUserOpTest,
    KernelERC1271Test,
    KernelExecutorTest,
    KernelValidatorTest,
    KernelExecuteTest,
    KernelSelectorTest,
    KernelHookTest
{
    function setUp() external {
        ep = EntryPointLib.deploy();

        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        helper = new KernelHelper();
        newValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        policy = new MockPolicy();
        signer = new MockSigner();
        permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        _initialize();
    }

    function _initialize() internal virtual override {
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
        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
        });
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));
    }

    function test_install_packages_with_signature_replayable() external unitTest {
        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
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
        MockHook mockHook = new MockHook();
        vm.expectRevert(NotImplemented.selector);
        kernel.installModule(10, address(mockHook), abi.encode(hex"", ""));
        vm.expectRevert(NotImplemented.selector);
        kernel.isModuleInstalled(10, address(mockHook), abi.encodePacked(permissionId));
    }

    function test_uninstall_invalid() external unitTest {
        MockHook mockHook = new MockHook();
        vm.expectRevert(NotImplemented.selector);
        kernel.uninstallModule(10, address(mockHook), abi.encode(hex"", ""));
    }
}
