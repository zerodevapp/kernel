// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {ModuleManager} from "src/core/ModuleManager.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {permissionToIdentifier} from "src/lib/Utils.sol";
import {InvalidPermissionId} from "src/types/Error.sol";

import {MockSigner} from "../mock/MockSigner.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockHook} from "../mock/MockHook.sol";

/// @notice Concrete `ModuleManager` subclass that exposes the internal
///         `_verifyStatelessSignature` as an external entry point so Halmos
///         can drive it directly with symbolic calldata.
/// @dev    The function under test is `view` and depends only on calldata +
///         the module addresses passed in `packages` (it does not read this
///         contract's storage). The harness therefore needs no setUp-time
///         state seeding beyond deploying the contract itself.
contract PermissionStatelessHarness is ModuleManager {
    /// @dev Required by Solady's `EIP712`. Trivial values for the harness.
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "PermissionStatelessHarness";
        version = "1";
    }

    /// @notice External passthrough so Halmos can call the internal
    ///         permission-branch loop with controlled, symbolic-friendly
    ///         calldata.
    function verifyStatelessExternal(
        Install[] calldata packages,
        ValidationId vId,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bool) {
        return _verifyStatelessSignature(packages, vId, hash, signature);
    }
}

/// @notice Halmos regression for commit `bfbef77`
///         ("fix: filter permission stateless match by module type").
///
/// Property under test
/// -------------------
///   In the permission branch of `_verifyStatelessSignature`, only packages
///   whose `moduleType` is `5` (POLICY) or `6` (SIGNER) AND whose
///   `internalData[0:4] == pId` may advance the `sigIdx` cursor. A package
///   whose `moduleType` is `1` (VALIDATOR), `2` (EXECUTOR), `3` (FALLBACK),
///   or `4` (HOOK) MUST NOT be consumed into the signature chain — even if
///   its `internalData[0:4]` happens to equal `pId`.
///
/// Why this matters
/// ----------------
///   Before `bfbef77` the loop body only filtered on
///   `internalData[0:4] == pId`. A package of the wrong module type could
///   therefore be enrolled in the chain. With at least two signatures in
///   the `PermissionSignature` array, that lets a non-policy module's
///   `validateSignatureWithDataWithSender` stand in for a real policy —
///   i.e. an attacker can install a module of any type whose `internalData`
///   starts with a victim's `pId` and have it satisfy the permission's
///   signature chain.
///
/// Encoding strategy
/// -----------------
///   - `packages.length = 2`. Smallest length that actually exercises the
///     bug: length 1 forces `sigIdx == signatures.length - 1` on the very
///     first match, which is blocked by the
///     `require(pkg.moduleType == 6, ...)` "last signature is signer"
///     check on EVERY branch (buggy and fixed).
///   - `pkg[0].moduleType` symbolic over `{1, 2, 3, 4}` — the suspect non
///     policy / non signer types.
///   - `pkg[1].moduleType = 6` (a real `MockSigner`).
///   - Both packages set `internalData[0:4] = pId` so the
///     `bytes4(pkg.internalData) == pId` test always matches.
///   - `signatures.length = 2`, signed bytes are concrete (any value works
///     — the mocks ignore them).
///   - The mocks have their internal `success` flag set to `true`, so any
///     `validateSignatureWithDataWithSender` call they receive returns
///     `true`. This gives the buggy path every chance to (wrongly) return
///     `true` — a counterexample is interesting only when the buggy code
///     actively consumes the wrong-type module.
///
/// Calldata layout note
/// --------------------
///   `_verifyStatelessSignature` reads `permissionSig` via the inline
///   assembly trick `permissionSig := signature.offset`. This treats
///   `signature` as the encoded body of a `PermissionSignature calldata`
///   struct (one dynamic field `bytes[] signatures`). The layout is the
///   head (`offset to signatures = 0x20`) followed by the `bytes[]`.
///   `abi.encode(structInstance)` adds an EXTRA wrapper offset that the
///   assembly does NOT expect, so we encode the inner `bytes[]` directly
///   with `abi.encode(sigs)`, which produces exactly the layout above.
///
/// Expected result
/// ---------------
///   - On the FIXED implementation: every `check…` PASSES. The wrong-type
///     package is filtered out, `sigIdx` never reaches `signatures.length`,
///     and the function reverts with `InvalidPermissionId`.
///   - On the CURRENT (buggy) source at `master @ a836274`: each
///     bug-targeted check FAILS with a counterexample. The counterexamples
///     are the security finding — they demonstrate that any module type
///     whose `internalData` starts with `pId` is enrolled in the signature
///     chain regardless of `moduleType`.
contract PermissionStatelessHalmos is SymTest, Test {
    PermissionStatelessHarness harness;
    MockValidator validatorModule; // moduleType == 1
    MockHook hookModule; // moduleType == 4
    MockSigner signerModule; // moduleType == 6

    function setUp() external {
        harness = new PermissionStatelessHarness();
        validatorModule = new MockValidator();
        hookModule = new MockHook();
        signerModule = new MockSigner();
    }

    // -------------------------------------------------------------------
    // Sanity: confirm the harness is actually wired up so PASSes on the
    // bug-targeted checks above are not vacuous.
    // -------------------------------------------------------------------

    /// @notice With one legitimate signer package matching `pId` and a
    ///         single-element `signatures` array, the function MUST accept.
    ///         A failure here means the harness is broken — every other
    ///         result in this file should be treated as suspect.
    function checkSanitySinglePolicyAccepts() external {
        _primeMocksForAcceptance();
        bytes4 pIdBytes = svm.createBytes4("pId_sanity");
        bytes memory matchingInternalData = abi.encodePacked(pIdBytes);
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(pIdBytes));

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: uint256(6), module: address(signerModule), moduleData: "", internalData: matchingInternalData
        });

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = hex"1111";
        bytes memory signature = abi.encode(sigs);

        bytes32 hash = svm.createBytes32("opHash_sanity");

        bool ok = harness.verifyStatelessExternal(packages, vId, hash, signature);
        assertTrue(ok, "single signer package should accept");
    }

    // -------------------------------------------------------------------
    // Bug-targeted checks (regression for bfbef77)
    // -------------------------------------------------------------------

    /// @notice Core regression: a `moduleType == 1` (VALIDATOR) package
    ///         cannot be enrolled into the permission signature chain just
    ///         because its `internalData[0:4]` equals `pId`. The function
    ///         MUST revert with `InvalidPermissionId`.
    function checkSigIdxDoesNotAdvanceForModuleType1() external {
        _checkRejectsWrongTypeAt0(uint256(1), address(validatorModule));
    }

    /// @notice Same regression for `moduleType == 4` (HOOK) — the other
    ///         module type explicitly called out in `bfbef77`. We strictly
    ///         require the revert reason to be `InvalidPermissionId`; any
    ///         other revert means the loop body ran for the Hook package
    ///         (e.g. it reached the now-non-existent
    ///         `validateSignatureWithDataWithSender` selector on
    ///         `MockHook` and reverted there).
    function checkSigIdxDoesNotAdvanceForModuleType4() external {
        _checkRejectsWrongTypeAt0(uint256(4), address(hookModule));
    }

    /// @notice Symbolic generalization: quantify over every suspect
    ///         module type in `{1, 2, 3, 4}` and assert the function
    ///         rejects all of them. Halmos splits this into one path per
    ///         type so the counterexamples (on buggy code) identify
    ///         exactly which types break the property.
    function checkSigIdxDoesNotAdvanceForAnyNonPolicySignerType() external {
        uint256 wrongType = svm.createUint256("wrongModuleType");
        vm.assume(wrongType == 1 || wrongType == 2 || wrongType == 3 || wrongType == 4);
        // We reuse `validatorModule` as the wrong-type stand-in. Its
        // `validateSignatureWithDataWithSender` returns `success`, so on
        // buggy code we get the strongest possible counterexample
        // (function returns `true`).
        _checkRejectsWrongTypeAt0(wrongType, address(validatorModule));
    }

    // -------------------------------------------------------------------
    // Internal scaffolding
    // -------------------------------------------------------------------

    /// @dev Set the `success` flag on every mock module to `true`. This
    ///      gives the buggy path every opportunity to wrongly return
    ///      `true`, which is the strongest possible counterexample.
    function _primeMocksForAcceptance() internal {
        validatorModule.sudoSetSuccess(true);
        // MockSigner.validateSignatureWithDataWithSender reads the same
        // private `success` flag that `sudoSetPass` flips.
        signerModule.sudoSetPass(address(harness), bytes32(0), true);
    }

    /// @dev Build a 2-element `packages` array where index 0 has the
    ///      given (wrong) module type and index 1 is a legitimate signer.
    ///      Both packages set `internalData[0:4] = pId`. Then assert that
    ///      the call reverts with the precise `InvalidPermissionId`
    ///      selector.
    function _checkRejectsWrongTypeAt0(uint256 wrongType, address wrongModule) internal {
        _primeMocksForAcceptance();

        // Symbolic permission id (any concrete value works, but symbolic
        // gives Halmos more freedom).
        bytes4 pIdBytes = svm.createBytes4("pId");
        bytes memory matchingInternalData = abi.encodePacked(pIdBytes);

        // High byte 0x02 forces `getType(vId) == VALIDATION_TYPE_PERMISSION`
        // so the function dispatches into the loop we care about.
        ValidationId vId = permissionToIdentifier(PermissionId.wrap(pIdBytes));

        Install[] memory packages = new Install[](2);
        packages[0] =
            Install({moduleType: wrongType, module: wrongModule, moduleData: "", internalData: matchingInternalData});
        packages[1] = Install({
            moduleType: uint256(6), module: address(signerModule), moduleData: "", internalData: matchingInternalData
        });

        // `signatures.length = 2`. Concrete bytes contents — the mocks
        // ignore them.
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = hex"1111";
        sigs[1] = hex"2222";
        // See "Calldata layout note" in the contract NatSpec for why we
        // encode the inner bytes[] directly instead of using
        // `abi.encode(PermissionSignature(...))`.
        bytes memory signature = abi.encode(sigs);

        bytes32 hash = svm.createBytes32("opHash");

        // The property: the call MUST revert with `InvalidPermissionId`.
        // Halmos v0.3.3 does not support `vm.expectRevert(bytes4)`, so we
        // use the documented try/catch idiom from the project's FV plan.
        try harness.verifyStatelessExternal(packages, vId, hash, signature) returns (bool ok) {
            // Any successful return is a violation regardless of value:
            //   * `true`  => buggy code accepted a wrong-type module
            //   * `false` => the inner stateless call WAS reached and
            //                returned `false` — i.e. the wrong-type
            //                package was already consumed.
            ok; // silence unused-variable warning
            assertTrue(false, "wrong-type module was consumed (non-revert return)");
        } catch (bytes memory reason) {
            // The only acceptable revert reason on the fixed code is the
            // top-level
            //   `require(sigIdx == permissionSig.signatures.length,
            //            InvalidPermissionId())`.
            // Anything else (including an empty EVM revert from calling
            // a non-existent selector on a Hook / Executor module) means
            // the loop body ran for the wrong-type package — bfbef77 bug.
            assertTrue(reason.length >= 4, "empty/short revert: wrong-type module was called and reverted");
            bytes4 sel;
            assembly {
                sel := mload(add(reason, 0x20))
            }
            assertEq(
                bytes32(sel),
                bytes32(InvalidPermissionId.selector),
                "wrong revert reason: a non-InvalidPermissionId revert means the wrong-type package was consumed"
            );
        }
    }
}
