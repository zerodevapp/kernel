// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/factory/TempKernel.sol";
import "src/factory/MultiSigKernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/MultiSigValidator.sol";
import "src/factory/EIP1967Proxy.sol";
// test artifacts
import "src/test/TestValidator.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";
import "src/utils/SignatureDecoder.sol";

using ERC4337Utils for EntryPoint;

contract KernelMultiSigTest is Test, SignatureDecoder {
    Kernel kernel;
    KernelFactory factory;
    MultiSigKernelFactory multiSigFactory;
    EntryPoint entryPoint;
    MultiSigValidator validator;
    address owner1;
    uint256 owner1Key;
    address owner2;
    uint256 owner2Key;
    address owner3;
    uint256 owner3Key;
    uint256 threshold;
    address payable beneficiary;

    function setUp() public {
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        (owner3, owner3Key) = makeAddrAndKey("owner3");
        threshold = 2;
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);

        validator = new MultiSigValidator();
        multiSigFactory = new MultiSigKernelFactory(factory, validator, entryPoint);
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        multiSigFactory.setOwners(owners, threshold);

        kernel = Kernel(payable(multiSigFactory.createAccount(0)));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
        console.log("beneficiary", beneficiary);
    }

    function test_initialize_twice() external {
        vm.expectRevert();
        kernel.initialize(validator, abi.encodePacked(owner1));
    }

    function test_validate_signature() external {
        Kernel kernel2 = Kernel(payable(address(multiSigFactory.createAccount(1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory signatures;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, hash);
            signatures = abi.encodePacked(r, s, v);
        }
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        // signatures are sorted by address manually and packed (owner2 < owner1)
        // [TODO] - write a library to sort signatures
        assertEq(kernel2.isValidSignature(hash, signatures), Kernel.isValidSignature.selector);
    }

    function test_validate_signature_with_prefix() external {
        Kernel kernel2 = Kernel(payable(address(multiSigFactory.createAccount(1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory signatures;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, hash);
            signatures = abi.encodePacked(r, s, v);
        }
        {
            bytes32 hashWithPrefix = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, hashWithPrefix);
            // When signed with EIP-191 prefix, adjust v to be 27/28 + 4
            signatures = abi.encodePacked(signatures, r, s, v + 4);
        }
        // signatures are sorted by address manually and packed (owner2 < owner1)
        // [TODO] - write a library to sort signatures
        assertEq(kernel2.isValidSignature(hash, signatures), Kernel.isValidSignature.selector);
    }

    function test_revert_when_signer_unauthorized() external {
        Kernel kernel2 = Kernel(payable(address(multiSigFactory.createAccount(1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory signatures;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, hash);
            signatures = abi.encodePacked(r, s, v);
        }
        {
            (address nonOwner, uint256 nonOwnerKey) = makeAddrAndKey("nonOwner");
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonOwnerKey, hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        assertEq(kernel2.isValidSignature(hash, signatures), bytes4(0xffffffff));
    }

    function test_revert_when_duplicate_signatures() external {
        Kernel kernel2 = Kernel(payable(address(multiSigFactory.createAccount(1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory signatures;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, hash);
            signatures = abi.encodePacked(r, s, v);
        }
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        assertEq(kernel2.isValidSignature(hash, signatures), bytes4(0xffffffff));
    }

    function test_revert_when_signatures_below_threshold() external {
        Kernel kernel2 = Kernel(payable(address(multiSigFactory.createAccount(1))));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory signatures;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, hash);
            signatures = abi.encodePacked(r, s, v);
        }
        assertEq(kernel2.isValidSignature(hash, signatures), bytes4(0xffffffff));
    }

    function test_set_default_validator() external {
        TestValidator newValidator = new TestValidator();
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.setDefaultValidator.selector, address(newValidator), empty)
        );
        op.signature = abi.encodePacked(bytes4(0x00000000));
        {
            bytes memory signature = entryPoint.signUserOpHash(vm, owner2Key, op);
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
            signature = abi.encodePacked(r, s, v + 4);
            op.signature = abi.encodePacked(op.signature, signature);
        }
        {
            bytes memory signature = entryPoint.signUserOpHash(vm, owner1Key, op);
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
            signature = abi.encodePacked(r, s, v + 4);
            op.signature = abi.encodePacked(op.signature, signature);
        }

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(KernelStorage(address(kernel)).getDefaultValidator()), address(newValidator));
    }

    function test_disable_mode() external {
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = abi.encodePacked(bytes4(0x00000000));
        {
            bytes memory signature = entryPoint.signUserOpHash(vm, owner2Key, op);
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
            signature = abi.encodePacked(r, s, v + 4);
            op.signature = abi.encodePacked(op.signature, signature);
        }
        {
            bytes memory signature = entryPoint.signUserOpHash(vm, owner1Key, op);
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
            signature = abi.encodePacked(r, s, v + 4);
            op.signature = abi.encodePacked(op.signature, signature);
        }

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(uint256(bytes32(KernelStorage(address(kernel)).getDisabledMode())), 1 << 224);
    }

    function test_set_execution() external {
        console.log("owner1", owner1);
        console.log("owner2", owner2);
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                KernelStorage.setExecution.selector,
                bytes4(0xdeadbeef),
                address(0xdead),
                address(newValidator),
                uint48(0),
                uint48(0),
                bytes("")
            )
        );
        op.signature = abi.encodePacked(bytes4(0x00000000));
        {
            bytes memory signature = entryPoint.signUserOpHash(vm, owner2Key, op);
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
            signature = abi.encodePacked(r, s, v + 4);
            op.signature = abi.encodePacked(op.signature, signature);
        }
        {
            bytes memory signature = entryPoint.signUserOpHash(vm, owner1Key, op);
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
            signature = abi.encodePacked(r, s, v + 4);
            op.signature = abi.encodePacked(op.signature, signature);
        }

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        ExecutionDetail memory execution = KernelStorage(address(kernel)).getExecution(bytes4(0xdeadbeef));
        assertEq(execution.executor, address(0xdead));
        assertEq(address(execution.validator), address(newValidator));
        assertEq(uint256(execution.validUntil), uint256(0));
        assertEq(uint256(execution.validAfter), uint256(0));
    }

    function test_callcode() external {
        CallCodeTester t = new CallCodeTester();
        address(t).call{value: 1e18}("");
        Target target = new Target();
        t.callcodeTest(address(target));
        console.log("target balance", address(target).balance);
        console.log("t balance", address(t).balance);
        console.log("t slot1", t.slot1());
        console.log("t slot2", t.slot2());
    }
}

contract CallCodeTester {
    uint256 public slot1;
    uint256 public slot2;
    receive() external payable {
    }
    function callcodeTest(address _target) external {
        bool success;
        bytes memory ret;
        uint256 b = address(this).balance / 1000;
        bytes memory data;
        assembly {
            let result := callcode(gas(), _target, b, add(data, 0x20), mload(data), 0, 0)
            // Load free memory location
            let ptr := mload(0x40)
            // We allocate memory for the return data by setting the free memory location to
            // current free memory location + data size + 32 bytes for data size value
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            // Store the size
            mstore(ptr, returndatasize())
            // Store the data
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            // Point the return data to the correct memory location
            ret := ptr
            success := result
        }
        require(success, "callcode failed");
    }
}

contract Target {
    uint256 public count;
    uint256 public amount;
    fallback() external payable {
        count++;
        amount += msg.value; 
    }
}
