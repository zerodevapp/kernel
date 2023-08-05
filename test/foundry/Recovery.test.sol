// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/factory/RecoveryKernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/RecoveryPlugin.sol";
import "src/factory/EIP1967Proxy.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestERC721.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract RecoveryTest is Test {
    Kernel kernel;
    KernelFactory factory;
    RecoveryKernelFactory recoveryFactory;
    EntryPoint entryPoint;
    RecoveryPlugin validator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;

    address newOwner = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    bytes32 hash =
        0xaa744ba2ca576ec62ca0045eca00ad3917fdf7ffa34fbbae50828a5a69c1580e;
    bytes signature =
        hex"f0745420866c7ec0615a2fa25afaa271cd763596fb4b87fbde763f4cb9cfe142575c22419490fb9db86a6d18801c7919f49b9042619ee339ea200cd8ad533cf41b";
    bytes guardianmode = hex"00";
    bytes recoverymode = hex"01";
    bytes guardiandata = hex"5b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000000000000000064";

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);

        validator = new RecoveryPlugin();
        recoveryFactory = new RecoveryKernelFactory(
            factory,
            validator,
            entryPoint
        );

        kernel = Kernel(payable(recoveryFactory.createAccount(abi.encodePacked(
                guardianmode,
                abi.encodePacked(owner),
                guardiandata
            ), 0)));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_initialize_twice() external {
        vm.expectRevert();
        kernel.initialize(
            validator,
            abi.encodePacked(
                guardianmode,
                abi.encodePacked(owner),
                guardiandata
            )
        );
    }

    function test_initialize() public {
        Kernel newKernel = Kernel(
            payable(
                address(
                    new EIP1967Proxy(
                        address(factory.nextTemplate()),
                        abi.encodeWithSelector(
                            KernelStorage.initialize.selector,
                            validator,
                            abi.encodePacked(
                                guardianmode,
                                abi.encodePacked(owner),
                                guardiandata
                            )
                        )
                    )
                )
            )
        );
        assert(validator.getGuardianByIndex(address(newKernel), 0).guardian == newOwner);
        assert(validator.getGuardianByIndex(address(newKernel), 0).weight == 100);
        assert(validator.getGuardianByIndex(address(newKernel),0).approved == false);
    }

    function test_validate_signature() external {
        Kernel kernel2 = Kernel(payable(address(recoveryFactory.createAccount(abi.encodePacked(
                guardianmode,
                abi.encodePacked(owner),
                guardiandata
            ), 1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        assertEq(kernel2.isValidSignature(hash, abi.encodePacked(r, s, v)), Kernel.isValidSignature.selector);
    }

    function test_disable_mode() external {
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(uint256(bytes32(KernelStorage(address(kernel)).getDisabledMode())), 1 << 224);
    }
}
