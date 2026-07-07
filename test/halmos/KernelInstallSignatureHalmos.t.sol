pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @title KernelInstallSignatureHalmos
/// @notice Halmos formal verification tests for install signature verification
contract KernelInstallSignatureHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;
    MockValidator private newValidator;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);

        newValidator = new MockValidator();
    }

    /// @notice Verify that installModule with signature fails when root validator rejects
    function check_InstallModuleWithInvalidSignatureReverts() external {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig =
            hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde";

        // Root validator returns failure by default
        try kernel.installModule(false, 0, pkgs, sig) {
            assert(false);
        } catch {}
    }

    /// @notice Verify that installModule with signature succeeds when root validator accepts
    function check_InstallModuleWithValidSignatureSucceeds() external {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig =
            hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde";

        // Make root validator accept
        rootValidator.sudoSetValidSig(sig);

        // Should succeed
        kernel.installModule(false, 0, pkgs, sig);

        // Verify the module was installed
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));
    }

    /// @notice Verify that installModule with signature fails on wrong nonce
    function check_InstallModuleWithWrongNonceReverts() external {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig =
            hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde";

        rootValidator.sudoSetValidSig(sig);

        // Use nonce 1 instead of 0 (the current nonce) - should fail
        try kernel.installModule(false, 1, pkgs, sig) {
            assert(false);
        } catch {}
    }

    /// @notice Verify that after a successful installModule with signature, the nonce is consumed
    function check_InstallModuleNonceConsumed() external {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig =
            hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde";

        rootValidator.sudoSetValidSig(sig);

        // First install succeeds
        kernel.installModule(false, 0, pkgs, sig);

        // Create a different module for second install attempt
        MockValidator anotherValidator = new MockValidator();
        Install[] memory pkgs2 = new Install[](1);
        pkgs2[0] = Install({moduleType: 1, module: address(anotherValidator), moduleData: hex"", internalData: hex""});

        // Trying nonce 0 again should fail since it was already consumed
        try kernel.installModule(false, 0, pkgs2, sig) {
            assert(false);
        } catch {}
    }

    /// @notice Verify that installModule with signature can be called by anyone (critical for ERC-7702)
    function check_InstallModuleWithSignatureAnyoneCanCall() external {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig =
            hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde";

        rootValidator.sudoSetValidSig(sig);

        // Call from arbitrary address (not EP, not self)
        address randomCaller = address(uint160(uint256(keccak256("random"))));
        vm.startPrank(randomCaller);
        kernel.installModule(false, 0, pkgs, sig);
        vm.stopPrank();

        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));
    }

    /// @notice Verify that nonce increments sequentially: after using nonce 0, nonce 1 works
    function check_InstallModuleSequentialNonces() external {
        // First install with nonce 0
        Install[] memory pkgs1 = new Install[](1);
        pkgs1[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig1 =
            hex"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaa";

        rootValidator.sudoSetValidSig(sig1);
        kernel.installModule(false, 0, pkgs1, sig1);

        // Second install with nonce 1
        MockValidator anotherValidator = new MockValidator();
        Install[] memory pkgs2 = new Install[](1);
        pkgs2[0] = Install({moduleType: 1, module: address(anotherValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig2 =
            hex"11223344112233441122334411223344112233441122334411223344112233441122334411223344112233441122334411223344112233441122334411223344aa";

        rootValidator.sudoSetValidSig(sig2);
        kernel.installModule(false, 1, pkgs2, sig2);

        assertTrue(kernel.isModuleInstalled(1, address(anotherValidator), hex""));
    }
}
