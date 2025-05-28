pragma solidity ^0.8.0;

import "./Kernel.t.sol";
import {Lib4337} from "src/lib/Lib4337.sol";

contract Kernel7702Test is KernelTest {
    address owner;
    uint256 ownerKey;

    function _initialize() internal override {
        is7702 = true;
        (owner, ownerKey) = makeAddrAndKey("Owner");
        kernel = Kernel(payable(owner));
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(factory.template())));
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
}
