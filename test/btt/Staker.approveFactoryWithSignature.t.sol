// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {StakerBTTModifiers} from "./StakerBTTModifiers.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "src/types/Constants.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {Staker} from "src/Staker.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {InvalidSignature, InvalidOwner} from "src/types/Error.sol";

abstract contract Staker_approveFactoryWithSignature is StakerBTTModifiers {
    function setUp() public override {
        _initializeStaker();
    }

    function test_GivenTheOwnerIsAddressZero() external {
        // it should revert with InvalidOwner error
        // Deploy a new Staker with a real owner, then renounce ownership to set owner to address(0)
        Staker zeroOwnerStaker = new Staker(address(this));
        // Renounce ownership sets owner to address(0)
        zeroOwnerStaker.renounceOwnership();

        uint256 nonce = zeroOwnerStaker.nonces(factoryAddr);
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factoryAddr)), uint256(1), nonce
        );
        // Sign with any key - does not matter since owner is address(0)
        bytes32 digest = _hashTypedDataForStaker(structHash, address(zeroOwnerStaker));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(InvalidOwner.selector);
        zeroOwnerStaker.approveFactoryWithSignature(factoryAddr, true, signature);
    }

    modifier givenTheSignatureIsInvalid() override {
        _;
    }

    function test_GivenTheSignatureIsInvalid() external givenTheSignatureIsInvalid {
        // it should revert with InvalidSignature error
        // Use a completely bogus signature
        bytes memory signature = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));

        vm.expectRevert(InvalidSignature.selector);
        staker.approveFactoryWithSignature(factoryAddr, true, signature);
    }

    function test_GivenTheSignerIsWrongButValidECDSA() external givenTheSignatureIsInvalid {
        // it should revert with InvalidSignature error
        (, uint256 wrongKey) = makeAddrAndKey("wrongOwner");

        uint256 nonce = staker.nonces(factoryAddr);
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factoryAddr)), uint256(1), nonce
        );
        bytes32 digest = _hashTypedDataSansChainId(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(InvalidSignature.selector);
        staker.approveFactoryWithSignature(factoryAddr, true, signature);
    }

    function test_GivenTheNonceHasBeenReplayed() external {
        // it should revert with InvalidSignature error
        // First, do a valid approval to consume nonce 0
        uint256 nonce = staker.nonces(factoryAddr);
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factoryAddr)), uint256(1), nonce
        );
        bytes32 digest = _hashTypedDataSansChainId(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First call succeeds
        staker.approveFactoryWithSignature(factoryAddr, true, signature);

        // Replaying the same signature should fail because nonce has incremented
        vm.expectRevert(InvalidSignature.selector);
        staker.approveFactoryWithSignature(factoryAddr, true, signature);
    }

    modifier givenTheSignatureIsValid() override {
        _;
    }

    function test_GivenTheSignatureIsValid() external givenTheSignatureIsValid {
        // it should set the factory approval
        // it should allow cross-chain signatures sans chainId
        // it should increment the nonce for the factory
        uint256 nonceBefore = staker.nonces(factoryAddr);
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factoryAddr)), uint256(1), nonceBefore
        );
        bytes32 digest = _hashTypedDataSansChainId(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertFalse(staker.approved(factoryAddr), "Factory should not be approved before");

        staker.approveFactoryWithSignature(factoryAddr, true, signature);

        assertTrue(staker.approved(factoryAddr), "Factory should be approved via signature");
        assertEq(staker.nonces(factoryAddr), nonceBefore + 1, "Nonce should have incremented");
    }

    /// @dev Helper to compute the typed data hash for a specific staker address
    function _hashTypedDataForStaker(bytes32 structHash, address stakerAddr) internal pure returns (bytes32 digest) {
        bytes32 typehash = 0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;
        string memory name = "Staker";
        string memory version = "0.0.1";
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(0x00, typehash)
            mstore(0x20, keccak256(add(name, 0x20), mload(name)))
            mstore(0x40, keccak256(add(version, 0x20), mload(version)))
            mstore(0x60, stakerAddr)
            mstore(0x20, keccak256(0x00, 0x80))
            mstore(0x00, 0x1901)
            mstore(0x40, structHash)
            digest := keccak256(0x1e, 0x42)
            mstore(0x40, m)
            mstore(0x60, 0)
        }
    }
}
