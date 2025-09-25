pragma solidity ^0.8.0;

import {KernelTest} from "./Kernel.t.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Lib4337} from "src/lib/Lib4337.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Kernel} from "src/Kernel.sol";

contract Kernel7702Test is KernelTest {
    address owner;
    uint256 ownerKey;

    Kernel7702 template;

    function _initialize() internal override {
        template = new Kernel7702(ep);
        is7702 = true;
        (owner, ownerKey) = makeAddrAndKey("Owner");
        kernel = Kernel(payable(owner));
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(template)));
        vm.deal(owner, 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        override
        returns (bytes memory sig)
    {
        bytes32 hash = replay ? Lib4337.chainAgnosticUserOpHash(address(ep), op) : ep.getUserOpHash(op);
        return _rootSignHash(hash, success);
    }

    function _rootSignHash(bytes32 hash, bool success) internal override returns (bytes memory sig) {
        if (!success) {
            hash = keccak256(abi.encodePacked(hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function test_erc1271() external {
        bytes32 hash = bytes32(vm.randomBytes(32));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        kernel.isValidSignature(hash, abi.encodePacked(r,s,v));
    }
}
