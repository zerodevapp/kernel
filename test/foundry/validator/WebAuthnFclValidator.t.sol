// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
import "forge-std/Test.sol";
import {ERC4337Utils} from "../utils/ERC4337Utils.sol";
import {KernelTestBase} from "../KernelTestBase.sol";
import {TestExecutor} from "../mock/TestExecutor.sol";
import {TestValidator} from "../mock/TestValidator.sol";
import {P256Validator} from "src/validator/P256Validator.sol";
import {WebAuthnWrapper} from "src/utils/WebAuthnWrapper.sol";
import {WebAuthnFclValidator} from "src/validator/WebAuthnFclValidator.sol";
import {P256} from "p256-verifier/P256.sol";
import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";
import {IKernel} from "src/interfaces/IKernel.sol";

using ERC4337Utils for IEntryPoint;

contract WebAuthnFclValidatorTest is KernelTestBase {
    WebAuthnFclValidator webAuthNValidator;

    // Curve order (number of points)
    uint256 constant n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    // The public key of the owner
    uint256 x;
    uint256 y;

    function setUp() public {
        webAuthNValidator = new WebAuthnFclValidator();

        _initialize();
        (x, y) = _getPublicKey(ownerKey);
        _setAddress();
        _setExecutionDetail();
    }

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getValidatorSignature(UserOperation memory _op) internal view virtual override returns (bytes memory) {
        bytes32 _hash = entryPoint.getUserOpHash(_op);
        bytes memory signature = _generateWebAuthnSignature(ownerKey, _hash);
        return abi.encodePacked(bytes4(0x00000000), signature);
    }

    function getOwners() internal virtual override returns (address[] memory _owners) {
        _owners = new address[](1);
        _owners[0] = address(0);
        return _owners;
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function getInitializeData() internal view override returns (bytes memory) {
        return abi.encodeWithSelector(KernelStorage.initialize.selector, webAuthNValidator, abi.encode(x, y));
    }

    function test_default_validator_enable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(webAuthNValidator),
                0,
                abi.encodeWithSelector(webAuthNValidator.enable.selector, abi.encode(x, y)),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        (uint256 x2, uint256 y2) = WebAuthnFclValidator(address(webAuthNValidator)).getPublicKey(address(kernel));
        verifyPublicKey(x2, y2, x, y);
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(webAuthNValidator),
                0,
                abi.encodeWithSelector(P256Validator.disable.selector, ""),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        (uint256 x2, uint256 y2) = WebAuthnFclValidator(address(webAuthNValidator)).getPublicKey(address(kernel));
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

    function test_validate_signature() external override {
        Kernel kernel2 = Kernel(payable(factory.createAccount(address(kernelImpl), getInitializeData(), 3)));
        bytes32 _hash = keccak256(abi.encodePacked("hello world"));

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", ERC4337Utils._buildDomainSeparator(KERNEL_NAME, KERNEL_VERSION, address(kernel)), _hash
            )
        );

        bytes memory signature = _generateWebAuthnSignature(ownerKey, digest);

        assertEq(kernel.isValidSignature(_hash, signature), Kernel.isValidSignature.selector);
        assertEq(kernel2.isValidSignature(_hash, signature), bytes4(0xffffffff));
    }

    function test_fail_validate_wrongsignature() external override {
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory sig = getWrongSignature(hash);
        assertEq(kernel.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        bytes32 _hash = entryPoint.getUserOpHash(op);
        bytes memory signature = _generateWebAuthnSignature(ownerKey, _hash);
        return abi.encodePacked(bytes4(0x00000000), signature);
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        bytes32 _hash = entryPoint.getUserOpHash(op);
        bytes memory signature = _generateWebAuthnSignature(ownerKey + 1, _hash);
        return abi.encodePacked(bytes4(0x00000000), signature);
    }

    function signHash(bytes32 _hash) internal view override returns (bytes memory) {
        return _generateWebAuthnSignature(ownerKey, _hash);
    }

    function getWrongSignature(bytes32 _hash) internal view override returns (bytes memory) {
        return _generateWebAuthnSignature(ownerKey + 1, _hash);
    }

    function verifyPublicKey(uint256 actualX, uint256 actualY, uint256 expectedX, uint256 expectedY) internal {
        assertEq(actualX, expectedX, "Public key X component mismatch");
        assertEq(actualY, expectedY, "Public key Y component mismatch");
    }

    /// @dev Ensure that our flow to generate a webauthn signature is working
    function test_webAuthnSignatureGeneration(bytes32 _hash, uint256 _privateKey) public {
        vm.assume(_privateKey > 0);
        (uint256 pubX, uint256 pubY) = _getPublicKey(_privateKey);

        // The public key we will use
        uint256[2] memory pubKey = [pubX, pubY];

        // Build all the data required
        (
            bytes32 msgToSign,
            bytes memory authenticatorData,
            bytes1 authenticatorDataFlagMask,
            bytes memory clientData,
            bytes32 clientChallenge,
            uint256 clientChallengeDataOffset
        ) = _prepapreWebAuthnMsg(_hash);

        // Then sign them
        (uint256 r, uint256 s) = _getP256Signature(_privateKey, msgToSign);
        uint256[2] memory rs = [r, s];

        // Ensure the signature is valid
        bool isValid = WebAuthnWrapper.checkSignature(
            authenticatorData,
            authenticatorDataFlagMask,
            clientData,
            clientChallenge,
            clientChallengeDataOffset,
            rs,
            pubKey
        );
        assertEq(isValid, true);
    }

    /* -------------------------------------------------------------------------- */
    /*                      Signature & P256 helper functions                     */
    /* -------------------------------------------------------------------------- */

    /// @dev Generate a webauthn signature for the given `_hash` using the given `_privateKey`
    function _generateWebAuthnSignature(uint256 _privateKey, bytes32 _hash)
        internal
        view
        returns (bytes memory signature)
    {
        (
            bytes32 msgToSign,
            bytes memory authenticatorData,
            ,
            bytes memory clientData,
            ,
            uint256 clientChallengeDataOffset
        ) = _prepapreWebAuthnMsg(_hash);

        // Get the signature
        (uint256 r, uint256 s) = _getP256Signature(_privateKey, msgToSign);
        uint256[2] memory rs = [r, s];

        // Return the signature
        return abi.encode(authenticatorData, clientData, clientChallengeDataOffset, rs);
    }

    /// @dev Prepare all the base data needed to perform a webauthn signature o n the given `_hash`
    function _prepapreWebAuthnMsg(bytes32 _hash)
        internal
        pure
        returns (
            bytes32 msgToSign,
            bytes memory authenticatorData,
            bytes1 authenticatorDataFlagMask,
            bytes memory clientData,
            bytes32 clientChallenge,
            uint256 clientChallengeDataOffset
        )
    {
        // Base Mapping of the message
        clientChallenge = _hash;
        bytes memory encodedChallenge = bytes(Base64Url.encode(abi.encodePacked(_hash)));

        // Prepare the authenticator data (from a real webauthn challenge)
        authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        // Prepare the client data (starting from a real webauthn challenge, then replacing only the bytes needed for the challenge)
        bytes memory clientDataStart = hex"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22";
        bytes memory clientDataEnd =
            hex"222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303032222c2263726f73734f726967696e223a66616c73657d";
        clientData = bytes.concat(clientDataStart, encodedChallenge, clientDataEnd);
        clientChallengeDataOffset = 36;

        // Set the flag mask to 0x01 (User Presence)
        authenticatorDataFlagMask = authenticatorData[32];

        // Once we got all of our data, prepapre the msg to sign
        msgToSign = WebAuthnWrapper.formatWebAuthNChallenge(
            authenticatorData, authenticatorDataFlagMask, clientData, clientChallenge, clientChallengeDataOffset
        );
    }

    /// @dev Get a public key for a p256 user, from the given `_privateKey`
    function _getPublicKey(uint256 _privateKey) internal view returns (uint256, uint256) {
        return FCL_ecdsa_utils.ecdsa_derivKpub(_privateKey);
    }

    /// @dev Generate a p256 signature, from the given `_privateKey` on the given `_hash`
    function _getP256Signature(uint256 _privateKey, bytes32 _hash) internal view returns (uint256 r, uint256 s) {
        // Securely generate a random k value for each signature
        uint256 k = uint256(keccak256(abi.encodePacked(_hash, block.timestamp, block.prevrandao, _privateKey))) % n;
        while (k == 0) {
            k = uint256(keccak256(abi.encodePacked(k))) % n;
        }

        // Generate the signature using the k value and the private key
        (r, s) = FCL_ecdsa_utils.ecdsa_sign(_hash, k, _privateKey);

        // Ensure that s is in the lower half of the range [1, n-1]
        if (r == 0 || s == 0 || s > P256.P256_N_DIV_2) {
            s = n - s; // If s is in the upper half, use n - s instead
        }

        return (r, s);
    }
}
