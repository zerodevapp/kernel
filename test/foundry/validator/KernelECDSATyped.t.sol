// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
import "src/validator/ECDSATypedValidator.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "src/utils/ERC4337Utils.sol";
import {KernelTestBase} from "src/utils/KernelTestBase.sol";
import {TestExecutor} from "src/mock/TestExecutor.sol";
import {TestValidator} from "src/mock/TestValidator.sol";
import {IKernel} from "src/interfaces/IKernel.sol";

using ERC4337Utils for IEntryPoint;

/// @author @KONFeature
/// @title KernelECDSATypedTest
/// @notice Unit test on the Kernel ECDSA typed validator
contract KernelECDSATypedTest is KernelTestBase {
    ECDSATypedValidator private ecdsaTypedValidator;

    function setUp() public virtual {
        _initialize();
        ecdsaTypedValidator = new ECDSATypedValidator();
        defaultValidator = ecdsaTypedValidator;
        _setAddress();
        _setExecutionDetail();
    }

    function test_ignore() external {}

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function getValidatorSignature(UserOperation memory) internal view virtual override returns (bytes memory) {
        return "";
    }

    function getOwners() internal view override returns (address[] memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return owners;
    }

    function getInitializeData() internal view override returns (bytes memory) {
        return abi.encodeWithSelector(KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(owner));
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), _generateUserOpSignature(entryPoint, op, ownerKey));
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), _generateUserOpSignature(entryPoint, op, ownerKey + 1));
    }

    function signHash(bytes32 _hash) internal view override returns (bytes memory) {
        return _generateHashSignature(_hash, owner, address(kernel), ownerKey);
    }

    function getWrongSignature(bytes32 _hash) internal view override returns (bytes memory) {
        return _generateHashSignature(_hash, owner, address(kernel), ownerKey + 1);
    }

    function test_default_validator_enable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(ECDSATypedValidator.enable.selector, abi.encodePacked(address(0xdeadbeef))),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        address owner_ = ecdsaTypedValidator.getOwner(address(kernel));
        assertEq(owner_, address(0xdeadbeef), "owner should be 0xdeadbeef");
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(ECDSATypedValidator.disable.selector, ""),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        address owner_ = ecdsaTypedValidator.getOwner(address(kernel));
        assertEq(owner_, address(0), "owner should be 0");
    }

    /* -------------------------------------------------------------------------- */
    /*                               Helper methods                               */
    /* -------------------------------------------------------------------------- */

    /// @notice The type hash used for kernel user op validation
    bytes32 constant USER_OP_TYPEHASH = keccak256("AllowUserOp(address owner,address kernelWallet,bytes32 userOpHash)");

    /// @dev Generate the signature for a user op
    function _generateUserOpSignature(IEntryPoint _entryPoint, UserOperation memory _op, uint256 _privateKey)
        internal
        view
        returns (bytes memory)
    {
        // Get the kernel private key owner address
        address owner_ = vm.addr(_privateKey);

        // Get the user op hash
        bytes32 userOpHash = _entryPoint.getUserOpHash(_op);

        // Get the validator domain separator
        bytes32 domainSeparator = ecdsaTypedValidator.getDomainSeperator();
        bytes32 typedMsgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator, keccak256(abi.encode(USER_OP_TYPEHASH, owner_, _op.sender, userOpHash))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, typedMsgHash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice The type hash used for kernel signature validation
    bytes32 constant SIGNATURE_TYPEHASH = keccak256("KernelSignature(address owner,address kernelWallet,bytes32 hash)");

    /// @dev Generate the signature for a given hash for a kernel account
    function _generateHashSignature(bytes32 _hash, address _owner, address _kernel, uint256 _privateKey)
        internal
        view
        returns (bytes memory)
    {
        // Get the validator domain separator
        bytes32 domainSeparator = ecdsaTypedValidator.getDomainSeperator();
        bytes32 typedMsgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator, keccak256(abi.encode(SIGNATURE_TYPEHASH, _owner, _kernel, _hash))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, typedMsgHash);
        return abi.encodePacked(r, s, v);
    }
}
