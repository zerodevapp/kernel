// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {Staker} from "src/Staker.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "src/types/Constants.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {InvalidSignature, NotApprovedFactory} from "src/types/Error.sol";

/// @title Staker BTT Tests
/// @notice Tests for Staker following Branching Tree Technique
/// @dev Tree specification: test/btt/Staker.tree
contract Staker_Test is Test {
    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    IEntryPoint ep;
    Staker staker;
    KernelFactory factory;
    KernelUUPS uups;
    KernelImmutableECDSA immutableEcdsa;
    MockValidator rootValidator;

    address owner;
    uint256 ownerKey;
    bool internal _signatureIsValid;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        ep = EntryPointLib.deploy();
        (owner, ownerKey) = makeAddrAndKey("owner");

        staker = new Staker(owner);

        uups = new KernelUUPS(ep);
        immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);

        rootValidator = new MockValidator();
        rootValidator.sudoSetSuccess(true);

        // Fund the staker and owner
        vm.deal(address(staker), 100 ether);
        vm.deal(owner, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallerIsNotOwner() {
        address notOwner = makeAddr("notOwner");
        vm.deal(notOwner, 10 ether); // Fund notOwner so payable calls can be tested
        vm.startPrank(notOwner);
        _;
        vm.stopPrank();
    }

    modifier whenCallerIsOwner() {
        vm.startPrank(owner);
        _;
        vm.stopPrank();
    }

    modifier givenFactoryIsNotApproved() {
        vm.prank(owner);
        staker.approveFactory(address(factory), false);
        _;
    }

    modifier givenFactoryIsApproved() {
        vm.stopPrank(); // Stop any existing prank
        vm.prank(owner);
        staker.approveFactory(address(factory), true);
        _;
    }

    modifier givenSignatureIsValid() {
        _signatureIsValid = true;
        _;
    }

    modifier givenSignatureIsInvalid() {
        _signatureIsValid = false;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    APPROVE FACTORY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert with Unauthorized error when caller is not owner
    function test_RevertWhen_ApproveFactory_CallerNotOwner() external whenCallerIsNotOwner {
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.approveFactory(address(factory), true);
    }

    /// @notice it should set the factory as approved when caller is owner
    function test_WhenApproveFactory_CallerIsOwner() external whenCallerIsOwner {
        staker.approveFactory(address(factory), true);

        assertTrue(staker.approved(address(factory)), "Factory should be approved");
    }

    /// @notice it should remain approved if already approved (idempotent)
    function test_WhenApproveFactory_AlreadyApproved() external {
        // Approve first time
        vm.prank(owner);
        staker.approveFactory(address(factory), true);

        // Approve again (idempotent)
        vm.prank(owner);
        staker.approveFactory(address(factory), true);

        assertTrue(staker.approved(address(factory)), "Factory should still be approved");
    }

    /*//////////////////////////////////////////////////////////////
                    REVOKE FACTORY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert with Unauthorized error when caller is not owner
    function test_RevertWhen_RevokeFactory_CallerNotOwner() external givenFactoryIsApproved whenCallerIsNotOwner {
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.approveFactory(address(factory), false);
    }

    /// @notice it should set the factory as not approved when caller is owner
    function test_WhenRevokeFactory_CallerIsOwner() external givenFactoryIsApproved whenCallerIsOwner {
        staker.approveFactory(address(factory), false);

        assertFalse(staker.approved(address(factory)), "Factory should be revoked");
    }

    /// @notice it should remain not approved if not approved (idempotent)
    function test_WhenRevokeFactory_NotApproved() external whenCallerIsOwner {
        // Revoke when not approved
        staker.approveFactory(address(factory), false);

        assertFalse(staker.approved(address(factory)), "Factory should remain not approved");
    }

    /*//////////////////////////////////////////////////////////////
                APPROVE FACTORY WITH SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should approve factory when signature is valid
    function test_WhenApproveFactoryWithSignature_ValidSignature() external givenSignatureIsValid {
        uint256 nonce = staker.nonces(address(factory));
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(address(factory))), uint256(1), nonce
        );
        bytes32 digest = _hashTypedDataSansChainId(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signatureKey(), digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        staker.approveFactoryWithSignature(address(factory), true, signature);

        assertTrue(staker.approved(address(factory)), "Factory should be approved via signature");
    }

    /// @notice it should revert when signature is invalid (wrong signer)
    function test_RevertWhen_ApproveFactoryWithSignature_InvalidSignature() external givenSignatureIsInvalid {
        uint256 nonce = staker.nonces(address(factory));
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(address(factory))), uint256(1), nonce
        );
        bytes32 digest = _hashTypedDataSansChainId(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signatureKey(), digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(InvalidSignature.selector);
        staker.approveFactoryWithSignature(address(factory), true, signature);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPLOY WITH FACTORY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert when factory is not approved
    function test_RevertWhen_DeployWithFactory_NotApproved() external givenFactoryIsNotApproved {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        bytes memory deployData = abi.encodeWithSelector(KernelFactory.deploy.selector, packages, uint256(0));

        vm.expectRevert(NotApprovedFactory.selector);
        staker.deployWithFactory(address(factory), deployData);
    }

    /// @notice it should deploy via factory when factory is approved
    function test_WhenDeployWithFactory_Approved() external givenFactoryIsApproved {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        bytes memory deployData = abi.encodeWithSelector(KernelFactory.deploy.selector, packages, uint256(0));

        address account = staker.deployWithFactory(address(factory), deployData);

        assertTrue(account != address(0), "Account should be deployed");
        assertTrue(account.code.length > 0, "Account should have code");
    }

    /*//////////////////////////////////////////////////////////////
                            STAKE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert when caller is not owner
    function test_RevertWhen_Stake_CallerNotOwner() external whenCallerIsNotOwner {
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.stake{value: 1 ether}(ep, 1 days);
    }

    /// @notice it should add stake to EntryPoint when caller is owner
    function test_WhenStake_CallerIsOwner() external whenCallerIsOwner {
        uint256 stakeBefore = ep.getDepositInfo(address(staker)).stake;

        staker.stake{value: 1 ether}(ep, 1 days);

        uint256 stakeAfter = ep.getDepositInfo(address(staker)).stake;
        assertEq(stakeAfter - stakeBefore, 1 ether, "Stake should increase");
    }

    /*//////////////////////////////////////////////////////////////
                        UNLOCK STAKE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert when caller is not owner
    function test_RevertWhen_UnlockStake_CallerNotOwner() external whenCallerIsNotOwner {
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.unlockStake(ep);
    }

    /// @notice it should start unstake delay when caller is owner
    function test_WhenUnlockStake_CallerIsOwner() external whenCallerIsOwner {
        // First add stake
        staker.stake{value: 1 ether}(ep, 1 days);

        staker.unlockStake(ep);

        // Check that unstake delay started (withdrawTime should be set)
        IEntryPoint.DepositInfo memory info = ep.getDepositInfo(address(staker));
        assertTrue(info.withdrawTime > 0, "Withdraw time should be set");
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAW STAKE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert when caller is not owner
    function test_RevertWhen_WithdrawStake_CallerNotOwner() external whenCallerIsNotOwner {
        vm.expectRevert(Ownable.Unauthorized.selector);
        staker.withdrawStake(ep, payable(owner));
    }

    /// @notice it should revert when stake is still locked
    function test_RevertWhen_WithdrawStake_StillLocked() external whenCallerIsOwner {
        staker.stake{value: 1 ether}(ep, 1 days);
        staker.unlockStake(ep);

        // Try to withdraw immediately (still locked)
        // The withdrawTime will be block.timestamp + 1 days, and we're at block.timestamp = 1
        uint256 withdrawTime = block.timestamp + 1 days;
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.WithdrawalNotDue.selector, withdrawTime, block.timestamp));
        staker.withdrawStake(ep, payable(owner));
    }

    /// @notice it should transfer stake when unstake delay has passed
    function test_WhenWithdrawStake_DelayPassed() external whenCallerIsOwner {
        staker.stake{value: 1 ether}(ep, 1 days);
        staker.unlockStake(ep);

        // Fast forward past unstake delay
        vm.warp(block.timestamp + 2 days);

        uint256 ownerBalanceBefore = owner.balance;
        staker.withdrawStake(ep, payable(owner));
        uint256 ownerBalanceAfter = owner.balance;

        assertEq(ownerBalanceAfter - ownerBalanceBefore, 1 ether, "Owner should receive stake");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _signatureKey() internal returns (uint256) {
        if (_signatureIsValid) {
            return ownerKey;
        }
        (, uint256 wrongKey) = makeAddrAndKey("wrongOwner");
        return wrongKey;
    }

    function _hashTypedDataSansChainId(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256("Staker"),
                keccak256("0.0.1"),
                address(staker)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
