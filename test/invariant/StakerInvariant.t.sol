pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Staker} from "src/Staker.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "src/types/Constants.sol";

contract StakerInvariantHandler is Test {
    Staker public immutable staker;
    address public immutable owner;
    uint256 public immutable ownerKey;

    address[] public factories;
    mapping(address => bool) public expectedApproved;
    mapping(address => uint256) public expectedNonces;

    bytes32 internal constant _DOMAIN_TYPEHASH_SANS_CHAIN_ID =
        0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;

    constructor(Staker staker_, address owner_, uint256 ownerKey_) {
        staker = staker_;
        owner = owner_;
        ownerKey = ownerKey_;

        for (uint256 i = 0; i < 5; i++) {
            factories.push(address(uint160(uint256(keccak256(abi.encodePacked("factory", i))))));
        }
    }

    function factoryCount() external view returns (uint256) {
        return factories.length;
    }

    function approveFactory(uint256 index, bool approval) external {
        address factory = factories[index % factories.length];
        vm.prank(owner);
        staker.approveFactory(factory, approval);
        expectedApproved[factory] = approval;
    }

    function approveFactoryWithSignature(uint256 index, bool approval) external {
        address factory = factories[index % factories.length];
        bytes32 structHash = EfficientHashLib.hash(
            uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(factory)), approval ? 1 : 0, staker.nonces(factory)
        );
        bytes32 digest = _hashTypedDataSansChainId(address(staker), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        staker.approveFactoryWithSignature(factory, approval, abi.encodePacked(r, s, v));
        expectedApproved[factory] = approval;
        expectedNonces[factory]++;
    }

    function _hashTypedDataSansChainId(address addr, bytes32 structHash) internal pure returns (bytes32 digest) {
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

contract StakerInvariant is StdInvariant, Test {
    Staker private staker;
    StakerInvariantHandler private handler;
    address private owner;

    function setUp() external {
        (address ownerAddr, uint256 ownerKey) = makeAddrAndKey("Owner");
        owner = ownerAddr;
        staker = new Staker(ownerAddr);
        handler = new StakerInvariantHandler(staker, ownerAddr, ownerKey);
        targetContract(address(handler));
    }

    function invariant_staker_state_matches_handler() external {
        uint256 count = handler.factoryCount();
        for (uint256 i = 0; i < count; i++) {
            address factory = handler.factories(i);
            assertEq(staker.approved(factory), handler.expectedApproved(factory), "approval mismatch");
            assertEq(staker.nonces(factory), handler.expectedNonces(factory), "nonce mismatch");
        }
    }

    function invariant_owner_is_constant() external {
        assertEq(staker.owner(), owner);
    }
}
