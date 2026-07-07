// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Staker} from "src/Staker.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "src/types/Constants.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

/// @title Staker BTT Shared Modifiers
/// @notice Common setup and modifiers used across Staker BTT test contracts
/// @dev Inherit from this contract for all Staker BTT tests
abstract contract StakerBTTModifiers is Test {
    IEntryPoint ep;
    Staker staker;
    KernelFactory factory;
    MockValidator rootValidator;
    address owner;
    uint256 ownerKey;
    address factoryAddr;

    bytes32 internal constant _DOMAIN_TYPEHASH_SANS_CHAIN_ID =
        0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;

    function setUp() public virtual {
        _initializeStaker();
    }

    function _initializeStaker() internal virtual {
        ep = EntryPointLib.deploy();
        (owner, ownerKey) = makeAddrAndKey("owner");
        staker = new Staker(owner);
        factoryAddr = makeAddr("factory");

        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);

        rootValidator = new MockValidator();
        rootValidator.sudoSetSuccess(true);

        vm.deal(address(staker), 100 ether);
        vm.deal(owner, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        CALLER MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier whenTheCallerIsNotTheOwner() virtual {
        address notOwner = makeAddr("notOwner");
        vm.deal(notOwner, 10 ether);
        vm.startPrank(notOwner);
        _;
        vm.stopPrank();
    }

    modifier whenTheCallerIsTheOwner() virtual {
        vm.startPrank(owner);
        _;
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        FACTORY MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheFactoryIsApproved() virtual {
        vm.prank(owner);
        staker.approveFactory(address(factory), true);
        _;
    }

    modifier givenTheFactoryIsNotApproved() virtual {
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNATURE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheSignatureIsValid() virtual {
        _;
    }

    modifier givenTheSignatureIsInvalid() virtual {
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _hashTypedDataSansChainId(bytes32 structHash) internal view returns (bytes32 digest) {
        address addr = address(staker);
        string memory name = "Staker";
        string memory version = "0.0.1";
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(0x00, _DOMAIN_TYPEHASH_SANS_CHAIN_ID)
            mstore(0x20, keccak256(add(name, 0x20), mload(name)))
            mstore(0x40, keccak256(add(version, 0x20), mload(version)))
            mstore(0x60, addr)
            mstore(0x20, keccak256(0x00, 0x80))
            mstore(0x00, 0x1901)
            mstore(0x40, structHash)
            digest := keccak256(0x1e, 0x42)
            mstore(0x40, m)
            mstore(0x60, 0)
        }
    }
}
