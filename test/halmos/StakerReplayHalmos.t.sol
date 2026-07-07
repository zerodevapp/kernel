pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Staker} from "src/Staker.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "src/types/Constants.sol";

/// @notice Probe subclass that exposes the `_hashTypedDataSansChainId` internal
/// helper so Halmos can reason about the digest computation directly.
///
/// We must NOT change the domain or struct-hash logic — only expose the digest
/// the production contract actually uses.
contract StakerProbe is Staker {
    constructor(address _owner) Staker(_owner) {}

    function digestFor(address factory, bool approval, uint256 nonce) external view returns (bytes32) {
        return _hashTypedDataSansChainId(
            EfficientHashLib.hash(
                uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factory)), approval ? 1 : 0, nonce
            )
        );
    }
}

/// @notice Halmos proofs for `Staker.approveFactoryWithSignature` replay safety.
///
/// The replay-safety guarantee decomposes into three structural properties:
///
///   1. **Nonce advance** — every successful call increments `nonces[factory]` by exactly 1.
///   2. **Digest changes per call** — because the digest binds the current nonce, two
///      consecutive calls compute distinct digests, so the same signature cannot be
///      reused (ECDSA is deterministic over the message).
///   3. **Chain-id independence** — the digest does NOT depend on `block.chainid`,
///      matching the contract's documented cross-chain claim.
///
/// We prove (1), (2), (3) structurally. The "second call reverts" guarantee follows
/// from (1) + (2) + ECDSA determinism — the latter is a cryptographic assumption
/// Halmos models as an uninterpreted precompile.
contract StakerReplayHalmos is SymTest, Test {
    StakerProbe staker;
    address owner;

    function setUp() external {
        owner = svm.createAddress("owner");
        vm.assume(owner != address(0));
        staker = new StakerProbe(owner);
    }

    /// @notice After a successful `approveFactoryWithSignature`, `nonces[factory]` is exactly
    /// one greater than before. This is the core anti-replay state change.
    function checkApproveFactoryWithSignatureBumpsNonce() external {
        address factory = svm.createAddress("factory");
        bool approval = svm.createBool("approval");
        bytes memory signature = svm.createBytes(65, "signature");

        // Symbolise the per-factory nonce so the proof covers any starting value, not
        // just the freshly-deployed zero. Storage slot for mapping(address=>uint256)
        // at slot 1 (Staker layout: `approved` at slot 0, `nonces` at slot 1, since
        // Ownable/EIP712 reserve high slots).
        uint256 symNonce = svm.createUint256("startingNonce");
        // Bound the nonce so the post-increment cannot overflow — overflow would be a
        // separate concern (and unreachable in any realistic deployment).
        vm.assume(symNonce < type(uint256).max);
        bytes32 nonceSlot = keccak256(abi.encode(factory, uint256(1)));
        vm.store(address(staker), nonceSlot, bytes32(symNonce));

        uint256 nonceBefore = staker.nonces(factory);
        assertEq(nonceBefore, symNonce, "vm.store must seed nonce storage");

        // Call the production entrypoint with fully symbolic arguments.
        (bool success,) =
            address(staker).call(abi.encodeCall(Staker.approveFactoryWithSignature, (factory, approval, signature)));
        vm.assume(success);

        uint256 nonceAfter = staker.nonces(factory);
        assertEq(nonceAfter, nonceBefore + 1, "nonce must advance by exactly 1 after success");
    }

    /// @notice The digest a second (replay) call would compute strictly differs from the
    /// digest the first call computed, because the per-factory nonce was incremented.
    /// Combined with ECDSA determinism, this proves the same signature cannot validate twice.
    function checkApproveFactoryWithSignatureReplayDigestDiffers() external {
        address factory = svm.createAddress("factory");
        bool approval = svm.createBool("approval");
        bytes memory signature = svm.createBytes(65, "signature");

        uint256 nonceBefore = staker.nonces(factory);
        vm.assume(nonceBefore < type(uint256).max);

        // Digest the first call uses.
        bytes32 digest1 = staker.digestFor(factory, approval, nonceBefore);

        // Execute the first call symbolically; assume it succeeded so we are in the
        // replay scenario.
        (bool success,) =
            address(staker).call(abi.encodeCall(Staker.approveFactoryWithSignature, (factory, approval, signature)));
        vm.assume(success);

        // After success, the nonce slot advanced. The digest a second call would use
        // mirrors the new in-storage nonce.
        uint256 nonceAfter = staker.nonces(factory);
        bytes32 digest2 = staker.digestFor(factory, approval, nonceAfter);

        // The two digests are distinct, so the same signature cannot validate both.
        assertTrue(digest1 != digest2, "replay digest must differ from original digest");
    }

    /// @notice The digest is invariant under `block.chainid`. Two Staker instances with
    /// identical owner/factory/approval/nonce produce identical digests across chains,
    /// matching the contract's documented chain-agnostic claim. If this assertion ever
    /// fails, the contract is no longer chain-agnostic — a documentation/spec drift.
    function checkApproveFactoryWithSignatureDigestChainIdIndependent() external {
        // Two probes deployed at the *same* address via vm.etch are not necessary —
        // the digest depends on `address(this)`, not on `block.chainid`. We assert
        // chain-id independence on a single instance by switching the chain id between
        // queries.
        address factory = svm.createAddress("factory");
        bool approval = svm.createBool("approval");
        uint256 nonce = svm.createUint256("nonce");
        uint256 chainA = svm.createUint256("chainA");
        uint256 chainB = svm.createUint256("chainB");
        vm.assume(chainA != chainB);

        vm.chainId(chainA);
        bytes32 digestA = staker.digestFor(factory, approval, nonce);

        vm.chainId(chainB);
        bytes32 digestB = staker.digestFor(factory, approval, nonce);

        assertEq(digestA, digestB, "digest must not depend on block.chainid");
    }
}
