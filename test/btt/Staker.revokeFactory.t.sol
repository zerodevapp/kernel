// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {StakerBTTModifiers} from "./StakerBTTModifiers.sol";
import {Ownable} from "solady/auth/Ownable.sol";

abstract contract Staker_revokeFactory is StakerBTTModifiers {
    function setUp() public override {
        _initializeStaker();
    }

    function test_WhenTheCallerIsNotTheOwner() external {
        // it should revert with Unauthorized error

        // First approve the factory
        vm.prank(owner);
        staker.approveFactory(factoryAddr, true);

        address notOwner = makeAddr("notOwner");
        vm.deal(notOwner, 10 ether);

        vm.prank(notOwner);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.approveFactory(factoryAddr, false);
    }

    modifier whenTheCallerIsTheOwner() override {
        vm.startPrank(owner);
        _;
        vm.stopPrank();
    }

    function test_GivenTheFactoryIsApproved() external whenTheCallerIsTheOwner {
        // it should set the factory as not approved

        // First approve the factory
        staker.approveFactory(factoryAddr, true);
        assertTrue(staker.approved(factoryAddr), "Factory should be approved");

        // Revoke approval
        staker.approveFactory(factoryAddr, false);

        assertFalse(staker.approved(factoryAddr), "Factory should be revoked");
    }

    function test_GivenTheFactoryIsNotApproved() external whenTheCallerIsTheOwner {
        // it should remain not approved
        assertFalse(staker.approved(factoryAddr), "Factory should not be approved initially");

        // Revoke (already not approved) - should be idempotent
        staker.approveFactory(factoryAddr, false);

        assertFalse(staker.approved(factoryAddr), "Factory should still not be approved");
    }
}
