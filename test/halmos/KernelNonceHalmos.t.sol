pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {InvalidNonce} from "src/types/Error.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @title KernelNonceHalmos
/// @notice Halmos proofs for nonce management safety
contract KernelNonceHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        MockValidator rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
    }

    /// @notice Prove setNonce with seq <= current reverts
    function check_SetNonceNonDecreasing() external {
        uint192 key = 0;
        vm.startPrank(address(ep));
        kernel.setNonce(key, 5);

        // seq <= current should revert
        try kernel.setNonce(key, 3) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Prove setNonce with equal value reverts
    function check_SetNonceEqualReverts() external {
        uint192 key = 0;
        vm.startPrank(address(ep));
        kernel.setNonce(key, 5);

        try kernel.setNonce(key, 5) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Prove setNonce with strictly greater value succeeds
    function check_SetNonceStrictlyGreaterSucceeds() external {
        uint192 key = 0;
        vm.startPrank(address(ep));
        kernel.setNonce(key, 5);
        kernel.setNonce(key, 6);
        vm.stopPrank();

        uint256 fullNonce = kernel.nonce(key);
        assertEq(uint64(fullNonce), 6);
    }

    /// @notice Prove setValidNonceFrom with <= current reverts
    function check_SetValidNonceFromNonDecreasing() external {
        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(10);

        try kernel.setValidNonceFrom(5) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Prove setValidNonceFrom with equal value reverts
    function check_SetValidNonceFromEqualReverts() external {
        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(10);

        try kernel.setValidNonceFrom(10) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Prove that nonce(key) respects validNonceFrom
    function check_NonceRespectsValidNonceFrom() external {
        uint192 key = 42;
        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(100);
        vm.stopPrank();

        uint256 fullNonce = kernel.nonce(key);
        uint64 seq = uint64(fullNonce);
        assertGe(seq, 100, "nonce seq should be >= validNonceFrom");
    }

    /// @notice Prove that after setValidNonceFrom, a key with lower nonce gets upgraded
    function check_NonceUpgradedByValidNonceFrom() external {
        uint192 key = 1;
        vm.startPrank(address(ep));
        // Set nonce for key 1 to 5
        kernel.setNonce(key, 5);
        // Now set validNonceFrom to 50 (higher than 5)
        kernel.setValidNonceFrom(50);
        vm.stopPrank();

        uint256 fullNonce = kernel.nonce(key);
        uint64 seq = uint64(fullNonce);
        assertGe(seq, 50, "nonce should be upgraded to validNonceFrom");
    }

    /// @notice Prove nonce keys are independent
    function check_NonceKeysIndependent() external {
        uint192 key1 = 0;
        uint192 key2 = 1;

        vm.startPrank(address(ep));
        kernel.setNonce(key1, 100);
        vm.stopPrank();

        // key2 should not be affected
        uint256 nonce2 = kernel.nonce(key2);
        uint64 seq2 = uint64(nonce2);
        assertEq(seq2, 0, "key2 should be unaffected");
    }

    /// @notice Prove nonce layout: upper 192 bits are the key
    function check_NonceLayoutCorrect() external view {
        uint192 key = 42;
        uint256 fullNonce = kernel.nonce(key);
        uint192 recoveredKey = uint192(fullNonce >> 64);
        assertEq(recoveredKey, key, "key should be in upper 192 bits");
    }
}
