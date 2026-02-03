pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Staker} from "src/Staker.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "src/types/Constants.sol";

contract MockFactory {
    error Foo();

    function success() external returns (address) {
        return address(this);
    }

    function fail() external returns (address) {
        revert Foo();
    }
}

contract StakerTest is Test {
    Staker staker;
    address owner;
    uint256 ownerKey;
    IEntryPoint ep;

    function setUp() external {
        ep = EntryPointLib.deploy();
        (owner, ownerKey) = makeAddrAndKey("Owner");
        staker = new Staker(owner);
    }

    function test_owner() external {
        address newOwner = makeAddr("newOwner");
        vm.startPrank(owner);
        staker.transferOwnership(newOwner);
        vm.stopPrank();
        assertEq(newOwner, staker.owner());
    }

    function test_approve() external {
        address factory = makeAddr("factory");
        vm.startPrank(owner);
        staker.approveFactory(factory, true);
        vm.stopPrank();
        assertEq(staker.approved(factory), true);
    }

    bytes32 internal constant _DOMAIN_TYPEHASH_SANS_CHAIN_ID =
        0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;

    function test_approve_with_sig() external {
        address factory = makeAddr("factory");
        address addr = address(staker);
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factory)), 1, staker.nonces(factory)
        );
        bytes32 digest;
        string memory name = "Staker";
        string memory version = "0.0.1";
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(0x00, _DOMAIN_TYPEHASH_SANS_CHAIN_ID)
            mstore(0x20, keccak256(add(name, 0x20), mload(name)))
            mstore(0x40, keccak256(add(version, 0x20), mload(version)))
            mstore(0x60, addr)
            // Compute the digest.
            mstore(0x20, keccak256(0x00, 0x80)) // Store the domain separator.
            mstore(0x00, 0x1901) // Store "\x19\x01".
            mstore(0x40, structHash) // Store the struct hash.
            digest := keccak256(0x1e, 0x42)
            mstore(0x40, m) // Restore the free memory pointer.
            mstore(0x60, 0) // Restore the zero pointer.
        }

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        assertEq(staker.nonces(factory), 0);
        staker.approveFactoryWithSignature(factory, true, abi.encodePacked(r, s, v));
        assertEq(staker.nonces(factory), 1);
        vm.expectRevert();
        staker.approveFactoryWithSignature(factory, true, abi.encodePacked(r, s, v));
    }

    function test_deploy_approved_success() external {
        MockFactory factory = new MockFactory();
        vm.startPrank(owner);
        staker.approveFactory(address(factory), true);
        vm.stopPrank();
        assertEq(staker.approved(address(factory)), true);

        address result =
            staker.deployWithFactory(address(factory), abi.encodeWithSelector(MockFactory.success.selector));
        assertEq(result, address(factory));
    }

    function test_deploy_approved_fail() external {
        MockFactory factory = new MockFactory();
        vm.startPrank(owner);
        staker.approveFactory(address(factory), true);
        vm.stopPrank();
        assertEq(staker.approved(address(factory)), true);

        vm.expectRevert();
        staker.deployWithFactory(address(factory), abi.encodeWithSelector(MockFactory.fail.selector));
    }

    function test_deploy_not_approved() external {
        MockFactory factory = new MockFactory();
        assertEq(staker.approved(address(factory)), false);

        vm.expectRevert();
        staker.deployWithFactory(address(factory), abi.encodeWithSelector(MockFactory.success.selector));
    }

    function test_stake() external {
        vm.deal(owner, 10e18);
        vm.startPrank(owner);
        staker.stake{value: 1e18}(ep, 86400);
        vm.stopPrank();

        IStakeManager.DepositInfo memory info = ep.getDepositInfo(address(staker));
        assertEq(info.deposit, 0);
        assertEq(info.staked, true);
        assertEq(uint256(info.stake), 1e18);
    }

    function test_unstake() external {
        vm.deal(owner, 10e18);
        vm.startPrank(owner);
        staker.stake{value: 1e18}(ep, 86400);
        vm.stopPrank();

        IStakeManager.DepositInfo memory info = ep.getDepositInfo(address(staker));
        assertEq(info.deposit, 0);
        assertEq(info.staked, true);
        assertEq(uint256(info.stake), 1e18);

        vm.startPrank(owner);
        staker.unlockStake(ep);
        vm.stopPrank();

        info = ep.getDepositInfo(address(staker));
        assertEq(info.deposit, 0);
        assertEq(info.staked, false);
        assertEq(uint256(info.stake), 1e18);
    }

    function test_withdraw_stake() external {
        vm.deal(owner, 10e18);
        vm.startPrank(owner);
        staker.stake{value: 1e18}(ep, 86400);
        vm.stopPrank();

        IStakeManager.DepositInfo memory info = ep.getDepositInfo(address(staker));
        assertEq(info.deposit, 0);
        assertEq(info.staked, true);
        assertEq(uint256(info.stake), 1e18);

        vm.startPrank(owner);
        staker.unlockStake(ep);
        vm.stopPrank();

        info = ep.getDepositInfo(address(staker));
        assertEq(info.deposit, 0);
        assertEq(info.staked, false);
        assertEq(uint256(info.stake), 1e18);

        address payable recipient = payable(makeAddr("Recipient"));
        assertEq(recipient.balance, 0);
        vm.warp(block.timestamp + 86401);
        vm.startPrank(owner);
        staker.withdrawStake(ep, recipient);
        vm.stopPrank();

        info = ep.getDepositInfo(address(staker));
        assertEq(info.deposit, 0);
        assertEq(info.staked, false);
        assertEq(uint256(info.stake), 0);
        assertEq(recipient.balance, 1e18);
    }
}
