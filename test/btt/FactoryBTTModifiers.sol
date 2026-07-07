// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";

/// @title Factory BTT Shared Modifiers
/// @notice Common setup and modifiers used across KernelFactory BTT test contracts
/// @dev Inherit from this contract for all KernelFactory BTT tests
abstract contract FactoryBTTModifiers is Test {
    IEntryPoint ep;
    KernelFactory factory;
    MockValidator rootValidator;

    // State variables for BTT branch tracking
    bool internal _addressAlreadyDeployed;
    bool internal _packagesEmpty;
    address internal _ecdsaOwner;

    function _initializeFactory() internal virtual {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        rootValidator.sudoSetSuccess(true);
    }

    /*//////////////////////////////////////////////////////////////
                        UNIT TEST MODIFIER
    //////////////////////////////////////////////////////////////*/

    modifier unitTest() {
        _;
    }
}
