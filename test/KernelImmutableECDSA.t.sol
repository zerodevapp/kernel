pragma solidity ^0.8.0;

import "./Kernel.t.sol";
import {Lib4337} from "src/lib/Lib4337.sol";
import {ECDSAValidator} from "./mock/ECDSAValidator.sol";

contract KernelImmutableECDSATest is KernelTest {
    address owner;
    uint256 ownerKey;

    function _initialize() internal override {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        rootValidator = new ECDSAValidator();
        rootValidatorData = abi.encodePacked(owner);
        Install[] memory pkgs = new Install[](0);
        kernel = factory.deployECDSA(owner, pkgs, 0);
        vm.deal(address(kernel), 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", ""));
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
        console.log("Owner :", owner);
        console.log("Code :");
        console.logBytes(address(kernel).code);
        if (!success) {
            hash = keccak256(abi.encodePacked(hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }
}
