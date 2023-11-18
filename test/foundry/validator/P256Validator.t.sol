// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
import "src/lite/KernelLiteECDSA.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {CREATOR_0_6_BYTECODE, CREATOR_0_6_ADDRESS} from "I4337/artifacts/EntryPoint_0_6.sol";
import {ERC4337Utils} from "../utils/ERC4337Utils.sol";
import {KernelTestBase} from "../KernelTestBase.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {TestExecutor} from "../mock/TestExecutor.sol";
import {TestValidator} from "../mock/TestValidator.sol";
import {P256Validator} from "src/validator/P256Validator.sol";
import {P256Verifier} from "p256-verifier/P256Verifier.sol";
import {P256} from "p256-verifier/P256.sol";
import {LibString} from "solady/utils/LibString.sol";


using ERC4337Utils for IEntryPoint;
using LibString for uint256;

// contract P256ValidatorTest is KernelTestBase {


///make sure R and S aren't 0. Sidechain attacks.
contract P256ValidatorTest is Test {
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    P256Validator p256Validator;
    uint256 x;
    uint256 y;

    P256Verifier p256Verifier;

    Kernel kernel;
    Kernel kernelImpl;
    KernelFactory factory;
    IEntryPoint entryPoint;
    IKernelValidator defaultValidator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;
    address factoryOwner;

    bytes4 executionSig;
    ExecutionDetail executionDetail;

    function setUp() public {
        p256Validator = new P256Validator();

        p256Verifier = new P256Verifier();
        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, address(p256Verifier).code);

        _initialize();

  

        (x, y) = generatePublicKey(ownerKey);



        _setAddress();
        


        (uint256 x2, uint256 y2) = p256Validator.p256PublicKey(address(kernel));
        assertEq(x, x2);
        assertEq(y, y2);
    }

    function _initialize() internal {
        (owner, ownerKey) = makeAddrAndKey("owner");
        (factoryOwner,) = makeAddrAndKey("factoryOwner");
        beneficiary = payable(address(makeAddr("beneficiary")));
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        entryPoint = IEntryPoint(payable(ENTRYPOINT_0_6_ADDRESS));
        vm.etch(CREATOR_0_6_ADDRESS, CREATOR_0_6_BYTECODE);
        kernelImpl = new Kernel(entryPoint);
        factory = new KernelFactory(factoryOwner, entryPoint);
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();
    }

    function _setAddress() internal {
        kernel = Kernel(payable(address(factory.createAccount(address(kernelImpl), getInitializeData(), 0))));
        vm.deal(address(kernel), 1e30);
    }

    function generatePublicKey(uint256 privateKey) internal returns (uint256, uint256) {
        string[] memory inputs = new string[](3);
        inputs[0] = "python";
        inputs[1] = "pkc.py";
        inputs[2] = privateKey.toString();
        bytes memory output = vm.ffi(inputs);

        return abi.decode(output, (uint256, uint256));
    }

    function generateSignature(uint256 privateKey, bytes32 hash) internal returns (uint256, uint256) {
        string[] memory inputs = new string[](4);
        inputs[0] = "python";
        inputs[1] = "signature.py";
        inputs[2] = uint256(hash).toHexString(32);
        inputs[3] = privateKey.toString();
        bytes memory output = vm.ffi(inputs);

        return abi.decode(output, (uint256, uint256));
    }

    function test_utils(uint256 privateKey, bytes32 hash) external {
        // vm.assume(uint256(privateKey).toHexString().length == 64);
        vm.assume(hash != 0);
        vm.assume(privateKey != 0);
        (uint256 x, uint256 y) = generatePublicKeys(privateKey);
        (uint256 r, uint256 s) = generateSignature(privateKey, hash);
        
        vm.assume(x != 0);
        vm.assume(y != 0);
        vm.assume(r != 0);
        vm.assume(s != 0);
        assertEq(P256.verifySignatureAllowMalleability(hash, r, s, x, y), true);
    }

    function test_validate_signature() external {
        Kernel kernel2 = Kernel(payable(factory.createAccount(address(kernelImpl), getInitializeData(), 3)));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", ERC4337Utils._buildDomainSeparator(KERNEL_NAME, KERNEL_VERSION, address(kernel)), hash
            )
        );

       
        (uint256 x, uint256 y) = generatePublicKey(ownerKey);
        (uint256 r, uint256 s) = generateSignature(ownerKey, digest);

        assertEq(kernel.isValidSignature(hash, abi.encode(r, s)), Kernel.isValidSignature.selector);
        assertEq(kernel2.isValidSignature(hash, abi.encode(r, s)), bytes4(0xffffffff));
    }

    function test_sudo() external {
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function getInitializeData() internal view  returns (bytes memory) {
        return abi.encodeWithSelector(
            KernelStorage.initialize.selector,
            p256Validator,
            abi.encode(x, y) 
        );
    }

    function test_set_default_validator() external  {
        TestValidator newValidator = new TestValidator();
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.setDefaultValidator.selector, address(newValidator), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit UserOperationEvent(entryPoint.getUserOpHash(op), address(kernel), address(0), op.nonce, false, 0, 0);
        entryPoint.handleOps(ops, beneficiary);
    }

    function signUserOp(UserOperation memory op) internal  returns (bytes memory) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint256 r, uint256 s) = generateSignature(ownerKey, hash);
        return abi.encodePacked(bytes4(0x00000000), abi.encode(r, s));
    }

    function getWrongSignature(UserOperation memory op) internal  returns (bytes memory) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint256 r, uint256 s) = generateSignature(ownerKey + 1, hash);
        return abi.encodePacked(bytes4(0x00000000), abi.encode(r, s));
    }

    function signHash(bytes32 hash) internal returns (bytes memory) {
        (uint256 r, uint256 s) = generateSignature(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encode(r, s);
    }

    function getWrongSignature(bytes32 hash) internal returns (bytes memory) {
        (uint256 r, uint256 s) = generateSignature(ownerKey + 1, ECDSA.toEthSignedMessageHash(hash));
        return abi.encode(r, s);
    }
}
