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

        kernel = Kernel(payable(recoveryFactory.createAccount(owner, 0)));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_initialize_twice() external {
        vm.expectRevert();
        kernel.initialize(
            validator,
            abi.encodePacked(
                newOwner,
                hash,
                signature
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
                                newOwner,
                                hash,
                                signature
                            )
                        )
                    )
                )
            )
        );
        RecoveryPluginStorage memory storage_ = RecoveryPluginStorage(
            validator.recoveryPluginStorage(address(newKernel))
        );
        assertEq(storage_.owner, owner);
    }
}
