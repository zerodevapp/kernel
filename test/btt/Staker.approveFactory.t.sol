// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {StakerBTTModifiers} from "./StakerBTTModifiers.sol";
import {Ownable} from "solady/auth/Ownable.sol";

abstract contract Staker_approveFactory is StakerBTTModifiers {
    function setUp() public override {
        _initializeStaker();
    }

    function test_WhenTheCallerIsNotTheOwner() external {
        // it should revert with Unauthorized error
        address notOwner = makeAddr("notOwner");
        vm.deal(notOwner, 10 ether);

        vm.prank(notOwner);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.approveFactory(factoryAddr, true);
    }

    modifier whenTheCallerIsTheOwner() override {
        vm.startPrank(owner);
        _;
        vm.stopPrank();
    }

    function test_GivenTheFactoryIsNotApproved() external whenTheCallerIsTheOwner {
        // it should set the factory as approved
        assertFalse(staker.approved(factoryAddr), "Factory should not be approved initially");

        staker.approveFactory(factoryAddr, true);

        assertTrue(staker.approved(factoryAddr), "Factory should be approved after call");
    }

    function test_GivenTheFactoryIsAlreadyApproved() external whenTheCallerIsTheOwner {
        // it should remain approved

        // First approve
        staker.approveFactory(factoryAddr, true);
        assertTrue(staker.approved(factoryAddr), "Factory should be approved");

        // Approve again (idempotent)
        staker.approveFactory(factoryAddr, true);
        assertTrue(staker.approved(factoryAddr), "Factory should still be approved");
    }
}
