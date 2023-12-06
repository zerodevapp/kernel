// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "../utils/ERC4337Utils.sol";
import {KernelTestBase} from "../KernelTestBase.sol";
import {TestExecutor} from "../mock/TestExecutor.sol";
import {TestValidator} from "../mock/TestValidator.sol";
import {P256Validator} from "src/validator/P256Validator.sol";
import {P256Verifier} from "p256-verifier/P256Verifier.sol";
import {P256} from "p256-verifier/P256.sol";
import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {IKernel} from "src/interfaces/IKernel.sol";


using ERC4337Utils for IEntryPoint;

contract P256ValidatorTest is KernelTestBase {
    P256Verifier p256Verifier;
    P256Validator p256Validator;

    // Curve order (number of points)
    uint256 constant n =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;


    uint256 x;
    uint256 y;

    function setUp() public {
        p256Validator = new P256Validator();
        p256Verifier = new P256Verifier();

        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, address(p256Verifier).code);

        _initialize();
        (x, y) = generatePublicKey(ownerKey);
        _setAddress();
        _setExecutionDetail();
    }

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getValidatorSignature(UserOperation memory _op) internal view virtual override returns (bytes memory) {
        bytes32 hash = entryPoint.getUserOpHash(_op);
        (uint256 r, uint256 s) = generateSignature(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(bytes4(0x00000000), abi.encode(r, s));
    }

    function getOwners() internal virtual override returns (address[] memory _owners){
        _owners = new address[](1);
        _owners[0] = address(0);
        return _owners;
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function getInitializeData() internal view override returns (bytes memory) {
        return abi.encodeWithSelector(KernelStorage.initialize.selector, p256Validator, abi.encode(x, y));
    }

    function test_default_validator_enable() external override{
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(p256Validator),
                0,
                abi.encodeWithSelector(P256Validator.enable.selector, abi.encode(x, y)),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        (uint256 x2, uint256 y2) = P256Validator(address(p256Validator)).p256PublicKey(address(kernel));
        verifyPublicKey(x2, y2, x, y);
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(p256Validator),
                0,
                abi.encodeWithSelector(P256Validator.disable.selector, ""),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        (uint256 x2, uint256 y2) = P256Validator(address(p256Validator)).p256PublicKey(address(kernel));
        verifyPublicKey(x2, y2, 0, 0);
    }

    function test_external_call_batch_execute_success() external override {
        vm.skip(true);
    }

    function test_external_call_execute_success() external override {
        vm.skip(true);
    }
    
    function test_external_call_execute_delegatecall_success() external override {
        vm.skip(true);
    }

    function test_external_call_execute_delegatecall_fail() external override {
        vm.skip(true);
    }

    function test_external_call_default() external override {
        vm.skip(true);
    }

    function test_external_call_execution() external override {
        vm.skip(true);
    }

    function generatePublicKey(uint256 privateKey) internal view returns (uint256, uint256) {
        return FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
    }

    function generateSignature(uint256 privateKey, bytes32 hash) internal view returns (uint256 r, uint256 s) {
        // Securely generate a random k value for each signature
        uint256 k = uint256(keccak256(abi.encodePacked(hash, block.timestamp, block.difficulty, privateKey))) % n;
        while (k == 0) {
            k = uint256(keccak256(abi.encodePacked(k))) % n;
        }

        // Generate the signature using the k value and the private key
        (r, s) = FCL_ecdsa_utils.ecdsa_sign(hash, k, privateKey);

        // Ensure that s is in the lower half of the range [1, n-1]
        if (r == 0 || s == 0 || s > P256.P256_N_DIV_2) {
            s = n - s; // If s is in the upper half, use n - s instead
        }

        return (r, s);
    }

    function test_utils(uint256 privateKey, bytes32 hash) external {
        vm.assume(hash != 0);
        vm.assume(privateKey != 0);
        (uint256 x1, uint256 y1) = generatePublicKey(privateKey);
        (uint256 r, uint256 s) = generateSignature(privateKey, hash);
        
        vm.assume(x1 != 0);
        vm.assume(y1 != 0);
        vm.assume(r != 0);
        vm.assume(s < P256.P256_N_DIV_2);
        assertEq(P256.verifySignature(hash, r, s, x1, y1), true);
    }

    function test_validate_signature() external override {
        Kernel kernel2 = Kernel(payable(factory.createAccount(address(kernelImpl), getInitializeData(), 3)));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", ERC4337Utils._buildDomainSeparator(KERNEL_NAME, KERNEL_VERSION, address(kernel)), hash
            )
        );

        (uint256 r, uint256 s) = generateSignature(ownerKey, digest);

        assertEq(kernel.isValidSignature(hash, abi.encode(r, s)), Kernel.isValidSignature.selector);
        assertEq(kernel2.isValidSignature(hash, abi.encode(r, s)), bytes4(0xffffffff));
    }

    function test_fail_validate_wrongsignature() external override {
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory sig = getWrongSignature(hash);
        assertEq(kernel.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint256 r, uint256 s) = generateSignature(ownerKey, hash);
        return abi.encodePacked(bytes4(0x00000000), abi.encode(r, s));
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint256 r, uint256 s) = generateSignature(ownerKey + 1, hash);
        return abi.encodePacked(bytes4(0x00000000), abi.encode(r, s));
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        (uint256 r, uint256 s) = generateSignature(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encode(r, s);
    }

    function getWrongSignature(bytes32 hash) internal view override returns (bytes memory) {
        (uint256 r, uint256 s) = generateSignature(ownerKey + 1, ECDSA.toEthSignedMessageHash(hash));
        return abi.encode(r, s);
    }

    function verifyPublicKey(uint256 actualX, uint256 actualY, uint256 expectedX, uint256 expectedY) internal {
        assertEq(actualX, expectedX, "Public key X component mismatch");
        assertEq(actualY, expectedY, "Public key Y component mismatch");
    }
}
