pragma solidity ^0.8.0;

import {KernelTest} from "./Kernel.t.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Lib4337} from "src/lib/Lib4337.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {ERC1271_MAGICVALUE} from "src/types/Constants.sol";

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

    function test_7702_unwrapped_erc1271(bytes32 hash) external erc1271Test {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        (bytes4 ret) = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_7702_unwrapped_erc1271_offchain(bytes32 hash) external {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        (bytes4 ret) = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_change_root_check_vId_0() external unitTest {
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });

        kernel.setRoot(packages, false, hex"");

        kernel.setRoot(ValidationId.wrap(bytes20(0)));
    }
}
