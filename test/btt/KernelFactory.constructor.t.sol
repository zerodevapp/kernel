// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {FactoryBTTModifiers} from "./FactoryBTTModifiers.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {ImplementationNotDeployed} from "src/types/Error.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

abstract contract KernelFactory_constructor is FactoryBTTModifiers {
    function test_WhenUupsImplementationHasNoCode() external {
        // it should revert with ImplementationNotDeployed
        IEntryPoint _ep = EntryPointLib.deploy();
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(_ep);

        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(KernelUUPS(payable(address(0xdead))), immutableEcdsa);
    }

    function test_WhenImmutableEcdsaImplementationHasNoCode() external {
        // it should revert with ImplementationNotDeployed
        IEntryPoint _ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(_ep);

        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(uups, KernelImmutableECDSA(payable(address(0xdead))));
    }

    function test_WhenBothImplementationsAreDeployed() external {
        // it should set the UUPS immutable
        // it should set the IMMUTABLE_ECDSA immutable
        IEntryPoint _ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(_ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(_ep);

        KernelFactory f = new KernelFactory(uups, immutableEcdsa);

        assertEq(address(f.UUPS()), address(uups), "UUPS should be set");
        assertEq(address(f.IMMUTABLE_ECDSA()), address(immutableEcdsa), "IMMUTABLE_ECDSA should be set");
    }
}
