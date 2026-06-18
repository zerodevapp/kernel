pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @notice Public wrapper around Kernel7702._verifyFallbackSignature so Halmos
/// can call it externally. Inherits the exact production implementation;
/// only adds the public entrypoint.
contract Kernel7702Harness is Kernel7702 {
    constructor(IEntryPoint _entryPoint) Kernel7702(_entryPoint) {}

    function verifyFallbackSignature(bytes32 hash, bytes calldata sig) external view returns (bool) {
        return _verifyFallbackSignature(hash, sig);
    }
}

/// @notice Public wrapper around KernelImmutableECDSA._verifyFallbackSignature.
/// Must be invoked through an ERC-1967 proxy whose immutable args carry the
/// expected signer; calling on the implementation directly would read zero
/// args. The wrapper also exposes the args reader used by the implementation
/// so the equivalence check uses the same source-of-truth signer.
contract KernelImmutableECDSAHarness is KernelImmutableECDSA {
    constructor(IEntryPoint _entryPoint) KernelImmutableECDSA(_entryPoint) {}

    function verifyFallbackSignature(bytes32 hash, bytes calldata sig) external view returns (bool) {
        return _verifyFallbackSignature(hash, sig);
    }

    function expectedSigner() external view returns (address) {
        return address(uint160(bytes20(LibClone.argsOnERC1967(address(this), 0, 20))));
    }
}

/// @notice Halmos proof that `_verifyFallbackSignature` accepts a signature iff
/// `ECDSA.tryRecoverCalldata(hash, sig)` matches the contract's expected
/// signer. The "iff" is encoded as a bit-for-bit equivalence:
///
///     verifyFallbackSignature(hash, sig)
///         == (ECDSA.tryRecoverCalldata(hash, sig) == expectedSigner)
///
/// This is the strongest "iff" formulation: it covers both directions
/// (accepts when recovery matches, rejects when it doesn't), AND rules out
/// any side channel where the result depends on something other than the
/// recovery / expected-signer comparison (zero-address recovery,
/// mis-recovered address, sigError sentinels, etc.).
///
/// Two `check…` functions — one per contract — share the same predicate
/// shape but differ in how `expectedSigner` is sourced:
///   - Kernel7702: address(this) (EOA self under 7702 designation)
///   - KernelImmutableECDSA: signer baked into ERC-1967 immutable args
contract FallbackSignatureHalmos is SymTest, Test {
    Kernel7702Harness internal kernel7702;
    KernelImmutableECDSAHarness internal immutableImpl;
    KernelImmutableECDSAHarness internal immutableProxy;

    address internal constant ENTRY_POINT = address(0xEEE);
    address internal constant IMMUTABLE_SIGNER = address(0x51461);

    function setUp() external {
        kernel7702 = new Kernel7702Harness(IEntryPoint(ENTRY_POINT));

        immutableImpl = new KernelImmutableECDSAHarness(IEntryPoint(ENTRY_POINT));
        // Deploy ERC-1967 proxy with 20-byte immutable signer.
        address proxy = LibClone.deployERC1967(address(immutableImpl), abi.encodePacked(IMMUTABLE_SIGNER));
        immutableProxy = KernelImmutableECDSAHarness(payable(proxy));
    }

    // --------------------------------------------------------------------
    // Kernel7702: expectedSigner == address(this) (the harness itself).
    // --------------------------------------------------------------------

    function checkKernel7702FallbackAcceptsIffExpectedSigner(bytes32 hash, bytes calldata sig) external view {
        bool accepted = kernel7702.verifyFallbackSignature(hash, sig);
        address recovered = ECDSA.tryRecoverCalldata(hash, sig);
        bool shouldAccept = (recovered == address(kernel7702));

        // Bidirectional iff: accepts iff (and only iff) recovery matches expected signer.
        assertEq(accepted, shouldAccept, "Kernel7702: accept iff recovered == address(this)");
    }

    // --------------------------------------------------------------------
    // KernelImmutableECDSA: expectedSigner == bytes20 immutable arg.
    // Called through the ERC-1967 proxy so `argsOnERC1967` returns the
    // 20-byte signer stored at the end of the proxy's runtime bytecode.
    // --------------------------------------------------------------------

    function checkKernelImmutableECDSAFallbackAcceptsIffExpectedSigner(bytes32 hash, bytes calldata sig) external view {
        // Self-consistency: the signer read from immutable args must equal the
        // 20 bytes we baked in via deployERC1967. Guards against the harness
        // accidentally validating a different signer than the dispatch intends.
        assertEq(immutableProxy.expectedSigner(), IMMUTABLE_SIGNER, "immutable signer must equal deploy-time arg");

        bool accepted = immutableProxy.verifyFallbackSignature(hash, sig);
        address recovered = ECDSA.tryRecoverCalldata(hash, sig);
        bool shouldAccept = (recovered == IMMUTABLE_SIGNER);

        assertEq(accepted, shouldAccept, "KernelImmutableECDSA: accept iff recovered == immutable signer");
    }
}
