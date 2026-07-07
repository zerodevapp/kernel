// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @notice Harness that subclasses Kernel and exposes the internal install-signature
/// helpers as external entry points. Used to exercise `_verifyInstallSignatureRaw`
/// directly (Halmos cannot reach `internal` functions otherwise).
///
/// Bypasses the UUPS proxy + Initializable guard so that Halmos can deploy a fresh
/// instance per check. The harness initializes itself via `harness_init`.
/// @author taek <leekt216@gmail.com>
contract VerifyInstallSignatureHarness is Kernel {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {}

    /// @dev Required override; no-op since `harness_init` is the entry point used here.
    function initialize(Install[] calldata packages) external payable override {
        _initialize(packages);
    }

    /// @notice Externally callable thin wrapper around the dispatched property's target
    /// `_verifyInstallSignatureRaw`. Returns the packed validation result without
    /// mutating any state.
    function harness_verifyInstallSignatureRaw(
        bool replayable,
        uint256 _nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) external view returns (uint256 validationData) {
        return _verifyInstallSignatureRaw(replayable, _nonce, packages, signature);
    }

    /// @notice External wrapper around the nonce-bumping variant `_verifyInstallSignature`.
    /// Used by the replay-protection property.
    function harness_verifyInstallSignature(
        bool replayable,
        uint256 _nonce,
        Install[] calldata packages,
        bytes calldata signature
    ) external returns (bool success) {
        return _verifyInstallSignature(replayable, _nonce, packages, signature);
    }
}

/// @title VerifyInstallSignatureHalmos
/// @notice Halmos proofs for ModuleManager._verifyInstallSignatureRaw — the enable-mode
/// install signature gate. The property is "returns success iff signature recovers to
/// the root validator's signer."
///
/// **Strategy**: deploy a `VerifyInstallSignatureHarness` (Kernel subclass) and seed it
/// with a `MockValidator` as root. The mock's `isValidSignatureWithSender` returns
/// `ERC1271_MAGICVALUE` iff `keccak256(sig)` is in its `validSig` set; this is exactly
/// the gate the property is about (a hash-keyed "good signature" oracle). Each check
/// flips the oracle on or off and asserts the verifier's verdict matches.
///
/// **Bounds applied**:
///   - `packages.length == 1` (one install per bundle). Justification: the property is
///     about whether the signature gate accepts/rejects, not about the package-loop
///     behavior. Multi-package bundles would explode the symbolic search and bring no
///     additional coverage of the gate itself.
///   - `signature.length == 65`. Justification: ECDSA's canonical length. The harness
///     mock keys validity by `keccak256(sig)`, so any concrete fixed length works; 65
///     mirrors how real signatures are presented to `_verifyInstallSignatureRaw`.
///   - `_nonce == 0` (or whatever the current sequence is) where required, since
///     `_verifyInstallSignatureRaw` calls `_checkNonce` and reverts on mismatch.
///     `KernelNonceHalmos` already proves the nonce mechanism independently; here we
///     fix the nonce to the live sequence so the property under test (signature gate)
///     is not entangled with the nonce gate.
/// @author taek <leekt216@gmail.com>
contract VerifyInstallSignatureHalmos is SymTest, Test {
    VerifyInstallSignatureHarness private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;

    function setUp() external {
        ep = EntryPointLib.deploy();
        rootValidator = new MockValidator();
        kernel = new VerifyInstallSignatureHarness(ep);

        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel.initialize(pkgs);
    }

    /// @dev Build a one-package install bundle for a fresh (symbolic) module address.
    function _pkgs(address module) internal pure returns (Install[] memory pkgs) {
        pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: module, moduleData: hex"", internalData: hex""});
    }

    /// @notice When the root validator's signature oracle rejects the signature, the
    /// raw verifier MUST report failure (low-160 bits of validationData != 0).
    /// This is the negative direction of the iff.
    function checkRejectsBadSignature() external {
        // Symbolic 65-byte signature; the oracle has NOT been told this is valid.
        bytes memory sig = svm.createBytes(65, "sig");

        // Symbolic module address (the new module being installed).
        address newModule = svm.createAddress("newModule");

        // Bind to the current nonce sequence (which is 0 right after init).
        uint256 nonceInput = 0;

        Install[] memory pkgs = _pkgs(newModule);

        uint256 validationData = kernel.harness_verifyInstallSignatureRaw(false, nonceInput, pkgs, sig);

        // Failure is encoded as `validationData & low160 != 0` (Lib4337.checkValidation
        // returns false when the recovered address is non-zero). With the mock oracle
        // OFF, the verifier must report failure.
        assertTrue((validationData & uint256(type(uint160).max)) != 0, "bad sig must be rejected");
    }

    /// @notice When the root validator's signature oracle accepts the signature, the
    /// raw verifier MUST report success (low-160 bits of validationData == 0).
    /// This is the positive direction of the iff.
    function checkAcceptsGoodSignature() external {
        // Symbolic 65-byte signature, but the oracle is told this exact hash is valid.
        bytes memory sig = svm.createBytes(65, "sig");
        rootValidator.sudoSetValidSig(sig);

        // Symbolic module address.
        address newModule = svm.createAddress("newModule");

        uint256 nonceInput = 0;

        Install[] memory pkgs = _pkgs(newModule);

        uint256 validationData = kernel.harness_verifyInstallSignatureRaw(false, nonceInput, pkgs, sig);

        // Success: low 160 bits of validationData are zero (no aggregator / signer
        // address recovered as the "failed" sentinel).
        assertEq(validationData & uint256(type(uint160).max), 0, "good sig must be accepted");
    }

    /// @notice Once `_verifyInstallSignature` (the nonce-bumping wrapper) has been
    /// invoked with a given `_nonce`, a second invocation with the SAME nonce MUST
    /// revert from `_checkAndIncrementNonce(InvalidNonce)` — this is the replay
    /// protection. This property is on the wrapper (not `_verifyInstallSignatureRaw`
    /// itself, which is view), but it directly exercises the install-signature path.
    function checkNonceReplayProtected() external {
        bytes memory sig = svm.createBytes(65, "sig");
        rootValidator.sudoSetValidSig(sig);

        address newModule = svm.createAddress("newModule");
        uint256 nonceInput = 0;
        Install[] memory pkgs = _pkgs(newModule);

        // First call: nonce is fresh, signature is good ⇒ must succeed.
        bool firstOk = kernel.harness_verifyInstallSignature(false, nonceInput, pkgs, sig);
        assertTrue(firstOk, "first install signature call must succeed");

        // Second call with identical args: nonce has been bumped, must revert.
        (bool replayOk,) = address(kernel)
            .call(
                abi.encodeWithSelector(
                    VerifyInstallSignatureHarness.harness_verifyInstallSignature.selector, false, nonceInput, pkgs, sig
                )
            );
        assertFalse(replayOk, "replay of same nonce must revert");
    }
}
