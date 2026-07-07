// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";

abstract contract KernelFactory_getECDSAAddress is BTTModifiers {
    function test_GivenAnyPackagesAndNonce() external {
        // it should return the deterministic address without deploying
        // it should return the same address for the same signer, packages, and nonce
        // it should return different addresses for different signers, packages, or nonces
        address signer = makeAddr("ecdsaSigner");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        // Get predicted address without deploying
        address predicted = factory.getECDSAAddress(signer, packages, 0);

        // Verify no code at predicted address yet
        assertEq(predicted.code.length, 0, "Should not deploy on getECDSAAddress");
        assertTrue(predicted != address(0), "Should return non-zero address");

        // Same parameters should return same address
        address predicted2 = factory.getECDSAAddress(signer, packages, 0);
        assertEq(predicted, predicted2, "Same params should return same address");

        // Different signer should return different address
        address differentSigner = makeAddr("differentSigner");
        address predictedDiffSigner = factory.getECDSAAddress(differentSigner, packages, 0);
        assertTrue(predicted != predictedDiffSigner, "Different signer should return different address");

        // Different nonce should return different address
        address predictedDiffNonce = factory.getECDSAAddress(signer, packages, 1);
        assertTrue(predicted != predictedDiffNonce, "Different nonce should return different address");

        // Different packages should return different address
        Install[] memory differentPackages = new Install[](1);
        differentPackages[0] =
            Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        address predictedDiffPkg = factory.getECDSAAddress(signer, differentPackages, 0);
        assertTrue(predicted != predictedDiffPkg, "Different packages should return different address");

        // Verify getECDSAAddress matches actual deployment
        Kernel deployed = factory.deployECDSA(signer, packages, 0);
        assertEq(address(deployed), predicted, "Deployed address should match predicted");
    }
}
