// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {StakerBTTModifiers} from "./StakerBTTModifiers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Ownable} from "solady/auth/Ownable.sol";

abstract contract Staker_withdrawStake is StakerBTTModifiers {
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

        // Setup: stake, unlock, and wait for delay
        vm.prank(owner);
        staker.stake{value: 1 ether}(ep, 1 days);
        vm.prank(owner);
        staker.unlockStake(ep);
        vm.warp(block.timestamp + 2 days);

        // Try to withdraw as non-owner
        address notOwner = makeAddr("notOwner");
        vm.deal(notOwner, 10 ether);
        vm.prank(notOwner);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.withdrawStake(ep, payable(notOwner));
    }

    function test_WhenTheCallerIsTheOwner() external whenTheCallerIsTheOwner {
        // it should call withdrawStake on the EntryPoint with the recipient
        address payable recipient = payable(makeAddr("recipient"));
        uint256 stakeAmount = 1 ether;

        // Setup: stake, unlock, and wait for delay
        staker.stake{value: stakeAmount}(ep, 1 days);
        staker.unlockStake(ep);
        vm.warp(block.timestamp + 2 days);

        // Verify stake before withdrawal
        IEntryPoint.DepositInfo memory infoBefore = ep.getDepositInfo(address(staker));
        assertEq(infoBefore.stake, stakeAmount, "Stake should be present before withdrawal");

        uint256 recipientBalanceBefore = recipient.balance;

        // Withdraw stake
        staker.withdrawStake(ep, recipient);

        // Verify stake is withdrawn
        IEntryPoint.DepositInfo memory infoAfter = ep.getDepositInfo(address(staker));
        assertEq(infoAfter.stake, 0, "Stake should be 0 after withdrawal");
        assertEq(recipient.balance, recipientBalanceBefore + stakeAmount, "Recipient should receive stake");
    }
}
