pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Staker} from "src/Staker.sol";

/// @notice Minimal IStakeManager stub that swallows `addStake`, `unlockStake`,
/// and `withdrawStake` without reverting. Used so the owner-path proofs do
/// not depend on a concrete EntryPoint deployment — we are testing the
/// `onlyOwner` access-control layer, not the EntryPoint integration.
///
/// The stub deliberately returns no data and never reverts; if the AC
/// gate is bypassed and `msg.sender == owner`, the inner call succeeds
/// (so the function as a whole succeeds) and we can assert that fact.
contract MockEntryPoint {
    function addStake(uint32) external payable {}
    function unlockStake() external {}
    function withdrawStake(address payable) external {}
}

/// @notice Halmos proofs for `Staker`'s `onlyOwner`-gated functions.
///
/// Property under proof (per dispatch):
///
///   Each of {approveFactory, stake, unlockStake, withdrawStake} reverts when
///   `msg.sender != owner()` (Solady's `Unauthorized()` revert, selector
///   0x82b42900), and does NOT revert on the auth check when
///   `msg.sender == owner()`.
///
/// We use low-level `.call` to capture revert data — that gives us a
/// solver-friendly boolean over success/failure without depending on
/// `vm.expectRevert` selector matching across Halmos versions.
///
/// For the owner-success branch on the three EntryPoint-touching functions
/// (stake / unlockStake / withdrawStake), we point `entryPoint` at a stub
/// `MockEntryPoint` that swallows the call. This keeps the proof focused on
/// the `onlyOwner` gate and avoids coupling to real EntryPoint semantics.
contract StakerOnlyOwnerHalmos is SymTest, Test {
    Staker private staker;
    MockEntryPoint private mockEp;
    address private ownerAddr;

    /// Solady `Unauthorized()` selector: bytes4(keccak256("Unauthorized()"))
    bytes4 private constant UNAUTHORIZED_SELECTOR = 0x82b42900;

    function setUp() external {
        ownerAddr = svm.createAddress("ownerAddr");
        vm.assume(ownerAddr != address(0));
        staker = new Staker(ownerAddr);
        mockEp = new MockEntryPoint();
    }

    // ------------------------------------------------------------------
    // approveFactory(address,bool)
    // ------------------------------------------------------------------

    /// @notice For any caller distinct from the owner, `approveFactory` must
    /// revert with the Solady `Unauthorized()` selector.
    function checkApproveFactoryRevertsForNonOwner() external {
        address caller = svm.createAddress("caller");
        address factory = svm.createAddress("factory");
        bool approval = svm.createBool("approval");
        vm.assume(caller != ownerAddr);

        vm.prank(caller);
        (bool success, bytes memory ret) =
            address(staker).call(abi.encodeCall(Staker.approveFactory, (factory, approval)));

        assertFalse(success, "approveFactory must revert for non-owner caller");
        assertEq(ret.length, 4, "revert data must be a 4-byte selector");
        assertEq(bytes4(ret), UNAUTHORIZED_SELECTOR, "must revert with Unauthorized()");
    }

    /// @notice When the owner calls `approveFactory`, the call does not
    /// revert at the access-control layer (and in fact returns successfully
    /// since there is no further failure path).
    function checkApproveFactorySucceedsForOwner() external {
        address factory = svm.createAddress("factory");
        bool approval = svm.createBool("approval");

        vm.prank(ownerAddr);
        (bool success,) = address(staker).call(abi.encodeCall(Staker.approveFactory, (factory, approval)));

        assertTrue(success, "approveFactory must succeed for owner caller");
    }

    // ------------------------------------------------------------------
    // stake(IEntryPoint,uint32)
    // ------------------------------------------------------------------

    /// @notice For any caller distinct from the owner, `stake` must revert
    /// with `Unauthorized()` — the AC gate fires before the EntryPoint call.
    function checkStakeRevertsForNonOwner() external {
        address caller = svm.createAddress("caller");
        IEntryPoint entryPoint = IEntryPoint(svm.createAddress("entryPoint"));
        uint32 unstakeDelay = uint32(svm.createUint256("unstakeDelay"));
        vm.assume(caller != ownerAddr);

        vm.prank(caller);
        (bool success, bytes memory ret) =
            address(staker).call(abi.encodeCall(Staker.stake, (entryPoint, unstakeDelay)));

        assertFalse(success, "stake must revert for non-owner caller");
        assertEq(ret.length, 4, "revert data must be a 4-byte selector");
        assertEq(bytes4(ret), UNAUTHORIZED_SELECTOR, "must revert with Unauthorized()");
    }

    /// @notice When the owner calls `stake`, the AC gate does not fire and
    /// the (stubbed) EntryPoint accepts the addStake call, so the whole call
    /// succeeds.
    function checkStakeSucceedsForOwner() external {
        uint32 unstakeDelay = uint32(svm.createUint256("unstakeDelay"));

        vm.prank(ownerAddr);
        (bool success,) =
            address(staker).call(abi.encodeCall(Staker.stake, (IEntryPoint(address(mockEp)), unstakeDelay)));

        assertTrue(success, "stake must succeed for owner caller with stub EntryPoint");
    }

    // ------------------------------------------------------------------
    // unlockStake(IEntryPoint)
    // ------------------------------------------------------------------

    /// @notice For any caller distinct from the owner, `unlockStake` must
    /// revert with `Unauthorized()`.
    function checkUnlockStakeRevertsForNonOwner() external {
        address caller = svm.createAddress("caller");
        IEntryPoint entryPoint = IEntryPoint(svm.createAddress("entryPoint"));
        vm.assume(caller != ownerAddr);

        vm.prank(caller);
        (bool success, bytes memory ret) = address(staker).call(abi.encodeCall(Staker.unlockStake, (entryPoint)));

        assertFalse(success, "unlockStake must revert for non-owner caller");
        assertEq(ret.length, 4, "revert data must be a 4-byte selector");
        assertEq(bytes4(ret), UNAUTHORIZED_SELECTOR, "must revert with Unauthorized()");
    }

    /// @notice When the owner calls `unlockStake`, the call succeeds against
    /// the stub EntryPoint.
    function checkUnlockStakeSucceedsForOwner() external {
        vm.prank(ownerAddr);
        (bool success,) = address(staker).call(abi.encodeCall(Staker.unlockStake, (IEntryPoint(address(mockEp)))));

        assertTrue(success, "unlockStake must succeed for owner caller with stub EntryPoint");
    }

    // ------------------------------------------------------------------
    // withdrawStake(IEntryPoint,address payable)
    // ------------------------------------------------------------------

    /// @notice For any caller distinct from the owner, `withdrawStake` must
    /// revert with `Unauthorized()`.
    function checkWithdrawStakeRevertsForNonOwner() external {
        address caller = svm.createAddress("caller");
        IEntryPoint entryPoint = IEntryPoint(svm.createAddress("entryPoint"));
        address payable recipient = payable(svm.createAddress("recipient"));
        vm.assume(caller != ownerAddr);

        vm.prank(caller);
        (bool success, bytes memory ret) =
            address(staker).call(abi.encodeCall(Staker.withdrawStake, (entryPoint, recipient)));

        assertFalse(success, "withdrawStake must revert for non-owner caller");
        assertEq(ret.length, 4, "revert data must be a 4-byte selector");
        assertEq(bytes4(ret), UNAUTHORIZED_SELECTOR, "must revert with Unauthorized()");
    }

    /// @notice When the owner calls `withdrawStake`, the call succeeds
    /// against the stub EntryPoint.
    function checkWithdrawStakeSucceedsForOwner() external {
        address payable recipient = payable(svm.createAddress("recipient"));

        vm.prank(ownerAddr);
        (bool success,) =
            address(staker).call(abi.encodeCall(Staker.withdrawStake, (IEntryPoint(address(mockEp)), recipient)));

        assertTrue(success, "withdrawStake must succeed for owner caller with stub EntryPoint");
    }
}
