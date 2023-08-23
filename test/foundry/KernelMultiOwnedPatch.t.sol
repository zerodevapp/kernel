// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import "src/factory/AdminLessERC1967Factory.sol";
import "src/factory/MultiECDSAFactory.sol";
import "src/factory/MultiECDSAFactoryPatch.sol";
import "src/Kernel.sol";
import "src/validator/MultiECDSAValidator.sol";
import "src/validator/MultiECDSAValidatorNew.sol";
import "src/test/TestValidator.sol";
import "src/test/TestExecutor.sol";
import "src/test/TestERC721.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils, KernelTestBase} from "./utils/ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract KernelMultiOwnedPatchTest is KernelTestBase {
    address secondOwner;
    uint256 secondOwnerKey;
    MultiECDSAFactoryPatch newFactory;
    MultiECDSAValidatorNew multiECDSAValidatorNew;
    address kernelImplementation;

    function setUp() public {
        _initialize();

        kernelImplementation = address(new Kernel(entryPoint));
        multiECDSAValidatorNew = new MultiECDSAValidatorNew();
        newFactory = new MultiECDSAFactoryPatch(
            factoryOwner,
            entryPoint,
            kernelImplementation,
            multiECDSAValidatorNew
        );

        vm.deal(address(factoryOwner), 1e30);
        vm.startPrank(factoryOwner);
        newFactory.setImplementation(kernelImplementation, true);

        (secondOwner, secondOwnerKey) = makeAddrAndKey("secondOwner");
        address[] memory owners = new address[](2);
        owners[0] = owner;
        owners[1] = secondOwner;
        newFactory.setOwners(owners);
        newFactory.addStake{value: 1}(1);
        vm.stopPrank();

        // factory = KernelFactory(address(newFactory));
        // _setAddress();
    }

    function testDeternimisticAddress() external {
        address proxy = newFactory.createAccount(2);
        assertEq(proxy, newFactory.getAccountAddress(2));
    }

    function test_execute_direct() external {
        address proxy = newFactory.createAccount(1);
        vm.startPrank(secondOwner);
        vm.deal(address(proxy), 1e30);
        Kernel(payable(proxy)).execute(secondOwner, 1, hex"", Operation.Call);
    }

    function test_execute() external {
        address proxy = newFactory.createAccount(1);
        assertEq(
            address(Kernel(payable(proxy)).getDefaultValidator()),
            address(multiECDSAValidatorNew)
        );
        UserOperation memory op = entryPoint.fillUserOp(
            address(proxy),
            abi.encodeWithSelector(
                Kernel.execute.selector,
                secondOwner,
                1,
                hex"",
                0
            )
        );
        op.signature = abi.encodePacked(
            bytes4(0x00000000),
            entryPoint.signUserOpHash(vm, secondOwnerKey, op)
        );
        vm.deal(address(proxy), 1e30);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        kernel = Kernel(payable(address(proxy)));
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
    }

    function getInitializeData() internal view returns (bytes memory) {
        return
            abi.encodeWithSelector(
                KernelStorage.initialize.selector,
                defaultValidator,
                abi.encodePacked(factory)
            );
    }

    function signUserOp(
        UserOperation memory op
    ) internal view returns (bytes memory) {
        return
            abi.encodePacked(
                bytes4(0x00000000),
                entryPoint.signUserOpHash(vm, ownerKey, op)
            );
    }

    function signHash(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ownerKey,
            ECDSA.toEthSignedMessageHash(
                keccak256(abi.encodePacked(hash, kernel))
            )
        );
        return abi.encodePacked(r, s, v);
    }
}
