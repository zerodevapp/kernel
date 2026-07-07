pragma solidity ^0.8.0;

import {KernelTest} from "./Kernel.t.sol";
import {ECDSAValidator} from "./mock/ECDSAValidator.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {InvalidRootValidation} from "src/types/Error.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";

contract KernelECDSATest is KernelTest {
    address owner;
    uint256 ownerKey;

    function _initialize() internal override {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        rootValidator = new ECDSAValidator();
        rootValidatorData = abi.encodePacked(owner);
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: 1, module: address(rootValidator), moduleData: abi.encodePacked(owner), internalData: hex""
        });
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", ""));
        vm.stopPrank();

        ValidationId vId = kernel.root();

        assertEq(ValidationId.unwrap(vId), bytes21(abi.encodePacked(bytes1(0x01), address(rootValidator))));
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        view
        override
        returns (bytes memory sig)
    {
        bytes32 hash = replay ? hashHelper.chainAgnosticUserOpHash(address(ep), op) : ep.getUserOpHash(op);
        return _rootSignHash(hash, success);
    }

    function _rootSignHash(bytes32 hash, bool success) internal view override returns (bytes memory sig) {
        if (!success) {
            hash = keccak256(abi.encodePacked(hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
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
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));

        kernel.setRoot(validatorToIdentifier(newValidator));

        vm.expectRevert(InvalidRootValidation.selector);
        kernel.setRoot(ValidationId.wrap(bytes21(0)));
    }
}
