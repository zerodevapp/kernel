// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {FactoryBTTModifiers} from "./FactoryBTTModifiers.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {InvalidSigner} from "src/types/Error.sol";
import {KernelDeployed} from "src/types/Events.sol";

abstract contract KernelFactory_deployECDSA is FactoryBTTModifiers {
    function test_WhenTheECDSAOwnerIsAddressZero() external {
        _initializeFactory();
        // it should revert with InvalidSigner error
        Install[] memory packages = new Install[](0);

        vm.expectRevert(InvalidSigner.selector);
        factory.deployECDSA(address(0), packages, 0);
    }

    modifier whenTheAddressIsAlreadyDeployedForThisOwnerAndNonce() {
        _addressAlreadyDeployed = true;
        _;
    }

    function test_WhenTheAddressIsAlreadyDeployedForThisOwnerAndNonce()
        external
        whenTheAddressIsAlreadyDeployedForThisOwnerAndNonce
    {
        _initializeFactory();
        // it should return the existing account address
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](0);

        // Deploy first time
        Kernel account1 = factory.deployECDSA(owner, packages, 0);

        // Deploy again with same params - should return existing
        Kernel account2 = factory.deployECDSA(owner, packages, 0);

        assertEq(address(account1), address(account2), "Should return existing account address");
    }

    function test_GivenMsgValueIsSentToAlreadyDeployed() external whenTheAddressIsAlreadyDeployedForThisOwnerAndNonce {
        _initializeFactory();
        // it should forward the ETH to the existing account
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](0);

        Kernel account = factory.deployECDSA(owner, packages, 0);
        uint256 balanceBefore = address(account).balance;

        vm.deal(address(this), 1 ether);
        factory.deployECDSA{value: 1 ether}(owner, packages, 0);

        assertEq(address(account).balance, balanceBefore + 1 ether, "ETH should be forwarded to existing account");
    }

    modifier whenTheECDSAOwnerIsAValidAddressAndNotYetDeployed() {
        _addressAlreadyDeployed = false;
        _ecdsaOwner = makeAddr("ecdsaOwner");
        _;
    }

    function test_WhenTheECDSAOwnerIsAValidAddressAndNotYetDeployed()
        external
        whenTheECDSAOwnerIsAValidAddressAndNotYetDeployed
    {
        _initializeFactory();
        // it should deploy a KernelImmutableECDSA proxy using CREATE2
        // it should initialize the account with the packages
        // it should return the deployed account address
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](0);

        Kernel account = factory.deployECDSA(owner, packages, 0);

        assertTrue(address(account) != address(0), "Account should be deployed");
        assertTrue(address(account).code.length > 0, "Account should have code");

        // Verify it's deterministic
        address predicted = factory.getECDSAAddress(owner, packages, 0);
        assertEq(address(account), predicted, "Deployed address should match predicted");
    }

    function test_GivenPackagesArrayHasValidModules_ShouldEmitKernelDeployed()
        external
        whenTheECDSAOwnerIsAValidAddressAndNotYetDeployed
    {
        _initializeFactory();
        // it should emit KernelDeployed event
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](0);

        address predicted = factory.getECDSAAddress(owner, packages, 70);

        vm.expectEmit(true, true, true, true);
        emit KernelDeployed(predicted);
        factory.deployECDSA(owner, packages, 70);
    }

    function test_WhenDeployingWithDifferentSignersAndSameNonce() external {
        _initializeFactory();
        // it should deploy to different addresses
        address owner1 = makeAddr("owner1");
        address owner2 = makeAddr("owner2");
        Install[] memory packages = new Install[](0);

        Kernel account1 = factory.deployECDSA(owner1, packages, 0);
        Kernel account2 = factory.deployECDSA(owner2, packages, 0);

        assertTrue(address(account1) != address(account2), "Different signers should deploy to different addresses");
    }
}
