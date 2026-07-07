pragma solidity ^0.8.0;

import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {Install, ValidationInfo} from "src/types/Structs.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {InvalidRootValidation, ImplementationNotDeployed} from "src/types/Error.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

contract KernelFactoryTest is KernelTestBase {
    function setUp() external {
        ep = EntryPointLib.deploy();

        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        newValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        policy = new MockPolicy();
        signer = new MockSigner();
        permissionId = PermissionId.wrap(bytes4(keccak256(abi.encodePacked("Hello world"))));
        vm.txGasPrice(1);
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

    function test_deploy_root_validator() external unitTest {
        vm.skip(is7702);
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: 1, module: address(rootValidator), moduleData: rootValidatorData, internalData: hex""
        });
        vm.startSnapshotGas("Mock - deploy()");
        factory.deploy(pkgs, 1);
        vm.stopSnapshotGas();
    }

    function test_deploy_root_permission() external unitTest {
        Install[] memory pkgs = new Install[](3);
        pkgs[0] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        pkgs[1] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        pkgs[2] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        Kernel k = factory.deploy(pkgs, 1);
        assertEq(k.accountId(), "kernel.v0.4");
        assertEq(k.registry(), address(0));
    }

    function test_deploy_root_fail_invalid_root() external unitTest {
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({moduleType: 2, module: address(executor), internalData: hex"", moduleData: hex""});
        pkgs[1] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        vm.expectRevert(InvalidRootValidation.selector);
        factory.deploy(pkgs, 1);
    }

    function test_deploy_existing() external {
        vm.skip(is7702);
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: 1, module: address(rootValidator), moduleData: rootValidatorData, internalData: hex""
        });
        Kernel k = factory.deploy(pkgs, 1);
        assertEq(address(k), address(factory.deploy(pkgs, 1)));
    }

    function test_deploy_with_value() external {
        vm.skip(is7702);
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: 1, module: address(rootValidator), moduleData: rootValidatorData, internalData: hex""
        });
        uint256 depositValue = 1 ether;
        vm.deal(address(this), depositValue);
        Kernel k = factory.deploy{value: depositValue}(pkgs, 2);
        assertEq(address(k).balance, depositValue);
    }

    function test_deploy_existing_with_value() external {
        vm.skip(is7702);
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: 1, module: address(rootValidator), moduleData: rootValidatorData, internalData: hex""
        });
        // First deploy
        factory.deploy(pkgs, 3);
        // Second deploy with value to same address
        uint256 depositValue = 1 ether;
        vm.deal(address(this), depositValue);
        Kernel k = factory.deploy{value: depositValue}(pkgs, 3);
        assertEq(address(k).balance, depositValue);
    }

    function test_constructor_reverts_when_uups_not_deployed() external {
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(KernelUUPS(payable(address(0xdead))), immutableEcdsa);
    }

    function test_constructor_reverts_when_immutableEcdsa_not_deployed() external {
        KernelUUPS uups = new KernelUUPS(ep);
        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(uups, KernelImmutableECDSA(payable(address(0xdead))));
    }

    function test_constructor_sets_immutables() external {
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory f = new KernelFactory(uups, immutableEcdsa);
        assertEq(address(f.UUPS()), address(uups));
        assertEq(address(f.IMMUTABLE_ECDSA()), address(immutableEcdsa));
    }

    function test_get_address() external view {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: 1, module: address(rootValidator), moduleData: rootValidatorData, internalData: hex""
        });
        address predicted = factory.getAddress(pkgs, 0);
        assertEq(predicted, address(kernel));
    }
}
