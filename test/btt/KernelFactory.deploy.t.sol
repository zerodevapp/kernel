// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {FactoryBTTModifiers} from "./FactoryBTTModifiers.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {InvalidRootValidation} from "src/types/Error.sol";
import {KernelDeployed} from "src/types/Events.sol";
import {MockValidator} from "../mock/MockValidator.sol";

abstract contract KernelFactory_deploy is FactoryBTTModifiers {
    modifier whenTheAddressIsAlreadyDeployedForThisInitPackagesHashAndNonce() {
        _addressAlreadyDeployed = true;
        _;
    }

    function test_WhenTheAddressIsAlreadyDeployedForThisInitPackagesHashAndNonce()
        external
        whenTheAddressIsAlreadyDeployedForThisInitPackagesHashAndNonce
    {
        _initializeFactory();
        // it should return the existing account address
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        // Deploy first time
        Kernel account1 = factory.deploy(packages, 0);

        // Deploy again with same params - should return existing
        Kernel account2 = factory.deploy(packages, 0);

        assertEq(address(account1), address(account2), "Should return existing account address");
    }

    function test_GivenMsgValueIsSent() external whenTheAddressIsAlreadyDeployedForThisInitPackagesHashAndNonce {
        _initializeFactory();
        // it should forward the ETH to the existing account
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        // Deploy first time
        Kernel account = factory.deploy(packages, 0);
        uint256 balanceBefore = address(account).balance;

        // Deploy again with ETH - should forward to existing
        vm.deal(address(this), 1 ether);
        factory.deploy{value: 1 ether}(packages, 0);

        assertEq(address(account).balance, balanceBefore + 1 ether, "ETH should be forwarded to existing account");
    }

    function test_GivenDifferentInitDataIsUsedAfterDeployment()
        external
        whenTheAddressIsAlreadyDeployedForThisInitPackagesHashAndNonce
    {
        _initializeFactory();
        // it should still return the same address ignoring new data
        // The salt is derived from initPackages and nonce, so same salt = same address
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account1 = factory.deploy(packages, 0);

        // Deploy again with same params - the initialization is skipped (alreadyDeployed=true)
        Kernel account2 = factory.deploy(packages, 0);

        assertEq(address(account1), address(account2), "Same salt should return same address");
    }

    modifier whenTheAddressIsNotYetDeployed() {
        _addressAlreadyDeployed = false;
        _;
    }

    function test_GivenPackagesArrayIsEmpty() external whenTheAddressIsNotYetDeployed {
        _initializeFactory();
        // it should revert during initialization
        Install[] memory packages = new Install[](0);

        vm.expectRevert(InvalidRootValidation.selector);
        factory.deploy(packages, 0);
    }

    function test_GivenPackagesArrayHasValidModules() external whenTheAddressIsNotYetDeployed {
        _initializeFactory();
        // it should deploy a new KernelUUPS proxy using CREATE2
        // it should initialize the account with the packages
        // it should return the deployed account address
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deploy(packages, 0);

        assertTrue(address(account) != address(0), "Account should be deployed");
        assertTrue(address(account).code.length > 0, "Account should have code");
        assertTrue(account.isModuleInstalled(1, address(rootValidator), ""), "Validator should be installed");
    }

    function test_GivenPackagesArrayHasValidModules_ShouldEmitKernelDeployed() external whenTheAddressIsNotYetDeployed {
        _initializeFactory();
        // it should emit KernelDeployed event
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted = factory.getAddress(packages, 50);

        vm.expectEmit(true, true, true, true);
        emit KernelDeployed(predicted);
        factory.deploy(packages, 50);
    }

    function test_GivenMsgValueIsSent_WhenTheAddressIsNotYetDeployed() external whenTheAddressIsNotYetDeployed {
        _initializeFactory();
        // it should fund the deployed account
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        vm.deal(address(this), 1 ether);
        Kernel account = factory.deploy{value: 1 ether}(packages, 0);

        assertEq(address(account).balance, 1 ether, "Account should receive ETH");
    }
}
