pragma solidity ^0.8.0;

import "./Kernel.t.sol";
import {Lib4337} from "src/lib/Lib4337.sol";
import {ECDSAValidator} from "./mock/ECDSAValidator.sol";

contract KernelECDSATest is KernelTest {
    address owner;
    uint256 ownerKey;
    ECDSAValidator ecdsaValidator;

    function _initialize() internal override {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        ecdsaValidator = new ECDSAValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(ecdsaValidator), moduleData: abi.encodePacked(owner), internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 1e18);
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
