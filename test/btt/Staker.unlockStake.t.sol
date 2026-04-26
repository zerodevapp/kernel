// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {StakerBTTModifiers} from "./StakerBTTModifiers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Ownable} from "solady/auth/Ownable.sol";

abstract contract Staker_unlockStake is StakerBTTModifiers {
    function setUp() public override {
        _initializeStaker();
    }

    modifier whenTheCallerIsTheOwner() override {
        vm.startPrank(owner);
        _;
        vm.stopPrank();
    }

    function test_WhenTheCallerIsNotTheOwner() external {
        // it should revert with Unauthorized error

        // First stake so there's something to unlock
        vm.prank(owner);
        staker.stake{value: 1 ether}(ep, 1 days);

        address notOwner = makeAddr("notOwner");
        vm.deal(notOwner, 10 ether);
        vm.prank(notOwner);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.unlockStake(ep);
    }

    function test_WhenTheCallerIsTheOwner() external whenTheCallerIsTheOwner {
        // it should call unlockStake on the EntryPoint

        // First stake so there's something to unlock
        staker.stake{value: 1 ether}(ep, 1 days);

        // Verify stake is locked
        IEntryPoint.DepositInfo memory infoBefore = ep.getDepositInfo(address(staker));
        assertTrue(infoBefore.staked, "Should be staked before unlock");
        assertEq(infoBefore.withdrawTime, 0, "Withdraw time should be 0 before unlock");

        // Unlock the stake
        staker.unlockStake(ep);

        // Verify unlock was initiated
        IEntryPoint.DepositInfo memory infoAfter = ep.getDepositInfo(address(staker));
        assertFalse(infoAfter.staked, "Should not be staked after unlock");
        assertTrue(infoAfter.withdrawTime > 0, "Withdraw time should be set after unlock");
    }
}
