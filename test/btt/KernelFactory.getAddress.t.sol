// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {FactoryBTTModifiers} from "./FactoryBTTModifiers.sol";
import {Install} from "src/types/Structs.sol";

abstract contract KernelFactory_getAddress is FactoryBTTModifiers {
    function test_GivenAnyPackagesAndNonce() external {
        _initializeFactory();
        // it should return the deterministic address without deploying
        // it should return the same address for the same packages and nonce
        // it should return different addresses for different packages or nonces

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        // Get address without deploying
        address predicted = factory.getAddress(packages, 0);
        assertTrue(predicted != address(0), "Predicted address should not be zero");
        assertTrue(predicted.code.length == 0, "Address should not have code yet");

        // Same packages and nonce should return same address
        address predicted2 = factory.getAddress(packages, 0);
        assertEq(predicted, predicted2, "Same inputs should return same address");

        // Different nonce should return different address
        address predicted3 = factory.getAddress(packages, 1);
        assertTrue(predicted != predicted3, "Different nonce should return different address");

        // Deploy and verify address matches
        address deployed = address(factory.deploy(packages, 0));
        assertEq(deployed, predicted, "Deployed address should match predicted");
    }
}
