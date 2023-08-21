// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/factory/RecoveryKernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/SocialRecoveryValidator.sol";
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
    SocialRecoveryValidator validator;
    address owner;
    uint256 ownerKey;
    address owner2 = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    uint256 ownerKey2 = 0x503f38a9c967ed597e47fe25643985f032b072db8075426a92110f82df48dfcb;
    address payable beneficiary;

    address newOwner = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    bytes32 hash =
        0xaa744ba2ca576ec62ca0045eca00ad3917fdf7ffa34fbbae50828a5a69c1580e;
    bytes signature =
        hex"edc77081733f99261f615f8de9f0a2474ad84fa54bc3e7925bc5a990efb4dbfd71df500dfd41f8da35cbd2179e55b1e31c998bc4371836e3f3aac6a390ab9f9e1b";

    bytes[] signatures = [signature];
    bytes guardianmode = hex"00";
    bytes recoverymode = hex"01";
    bytes recoveryByGuardianMode = hex"02";
    bytes setNewOwnerAddressMode = hex"03";
    bytes guardiandata = hex"5b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000000000000000064";
    bytes guardiandata2 = hex"a0Cb889707d426A7A386870A03bc70d1b069759800000000000000000000000000000000000000000000000000000000000000645b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000000000000000064";

    uint256 weight = 50;
    bytes32 weightinbytes = bytes32(weight);
    uint256 weight2 = 10;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);

        validator = new SocialRecoveryValidator();
        recoveryFactory = new RecoveryKernelFactory(
            factory,
            validator,
            entryPoint
        );

        kernel = Kernel(payable(recoveryFactory.createAccount(abi.encodePacked(
                guardianmode,
                weightinbytes,
                abi.encodePacked(owner),
                guardiandata
            ), 0)));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_initialize_twice() public {
        vm.expectRevert();
        kernel.initialize(
            validator,
            abi.encodePacked(
                guardianmode,
                weightinbytes,
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
                                weightinbytes,
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

    function test_validate_signature() public {
        Kernel kernel2 = Kernel(payable(address(recoveryFactory.createAccount(abi.encodePacked(
                                guardianmode,
                                weightinbytes,
                                abi.encodePacked(owner),
                                guardiandata
                            ), 1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        assertEq(kernel2.isValidSignature(hash, abi.encodePacked(r, s, v)), Kernel.isValidSignature.selector);
    }

    function test_disable_mode() public {
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

    function test_recovery() public {
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
                                weightinbytes,
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

        vm.deal(address(newKernel), 1e60);

        UserOperation memory op = entryPoint.fillUserOp(
            address(newKernel),
            abi.encodeWithSelector(Kernel.execute.selector, address(validator), 0, abi.encodeWithSelector(validator.enable.selector,abi.encodePacked(setNewOwnerAddressMode,newOwner)), Operation.Call)
        );

        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        assert(validator.newOwnerAddress(address(newKernel)) == newOwner);

        console.log(address(validator));
        validator.recoveryMessage(address(newKernel));

        UserOperation memory op1 = entryPoint.fillUserOp(
            address(newKernel),
            abi.encodeWithSelector(Kernel.execute.selector, address(validator), 0, abi.encodeWithSelector(validator.enable.selector,abi.encodePacked(recoverymode,signature)), Operation.Call)
        );

        op1.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op1));
        UserOperation[] memory ops1 = new UserOperation[](1);
        ops1[0] = op1;
        entryPoint.handleOps(ops1, beneficiary);

        RecoveryPluginStorage memory storage_ =
            RecoveryPluginStorage(validator.recoveryPluginStorage(address(newKernel)));
        assertEq(storage_.owner, newOwner);
    }
    function test_recovery_by_guardian() public {

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
                                bytes32(weight2),
                                abi.encodePacked(owner),
                                guardiandata2
                            )
                        )
                    )
                )
            )
        );


        Kernel newKernel2 = Kernel(
            payable(
                address(
                    new EIP1967Proxy(
                        address(factory.nextTemplate()),
                        abi.encodeWithSelector(
                            KernelStorage.initialize.selector,
                            validator,
                            abi.encodePacked(
                                guardianmode,
                                weightinbytes,
                                abi.encodePacked(owner),
                                guardiandata
                            )
                        )
                    )
                )
            )
        );

        console.log(address(newKernel));
        console.log(address(newKernel2));

        vm.deal(address(newKernel), 1e60);
        vm.deal(address(newKernel2), 1e60);
                
        assert(validator.getGuardianByIndex(address(newKernel), 0).guardian == address(newKernel2));

        UserOperation memory op = entryPoint.fillUserOp(
            address(newKernel),
            abi.encodeWithSelector(Kernel.execute.selector, address(validator), 0, abi.encodeWithSelector(validator.enable.selector,abi.encodePacked(setNewOwnerAddressMode,newOwner)), Operation.Call)
        );

        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        UserOperation memory op1 = entryPoint.fillUserOp(
            address(newKernel2),
            abi.encodeWithSelector(Kernel.execute.selector, address(validator), 0, abi.encodeWithSelector(validator.enable.selector,abi.encodePacked(recoveryByGuardianMode,address(newKernel),signature,signature)), Operation.Call)
        );

        op1.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op1));
        UserOperation[] memory ops1 = new UserOperation[](1);
        ops1[0] = op1;
        entryPoint.handleOps(ops1, beneficiary);

        RecoveryPluginStorage memory storage_1 =
            RecoveryPluginStorage(validator.recoveryPluginStorage(address(newKernel)));
        RecoveryPluginStorage memory storage_2 =
            RecoveryPluginStorage(validator.recoveryPluginStorage(address(newKernel2)));

        assertEq(storage_1.owner,newOwner);
    }
}
