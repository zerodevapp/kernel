// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FixedPointMathLib} from "solady/utils/FixedPointMathLib.sol";
import "src/Kernel.sol";
import {EllipticCurve} from "src/validator/stealthAddressValidator/EllipticCurve.sol";
import {IKernel} from "src/interfaces/IKernel.sol";
import {StealthAddressValidator} from "src/validator/stealthAddressValidator/StealthAddressValidator.sol";
// test utils
import {KernelTestBase} from "../KernelTestBase.sol";
import {TestExecutor} from "../mock/TestExecutor.sol";
import {TestValidator} from "../mock/TestValidator.sol";
import "forge-std/Vm.sol";

struct StealthAddressKey {
    address stealthAddress;
    uint256 stealthPub;
    uint256 dhPub;
    uint8 stealthPrefix;
    uint8 dhPrefix;
    uint256 ephemeralPub;
    uint8 ephemeralPrefix;
    uint256 hashSecret;
    uint256 stealthPrivate;
}

contract StealthAddressValidatorTest is KernelTestBase {
    StealthAddressValidator private stealthAddressValidator;
    VmSafe.Wallet private wallet;
    VmSafe.Wallet private ephemeralWallet;
    uint256 private stealthPrivateKey;

    function setUp() public {
        _initialize();
        wallet = vm.createWallet(uint256(keccak256(bytes("owner"))));
        ephemeralWallet = vm.createWallet(uint256(keccak256(bytes("ephemeral"))));

        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);
        owner = stealthAddressKey.stealthAddress;
        ownerKey = stealthAddressKey.stealthPrivate;
        stealthAddressValidator = new StealthAddressValidator();
        defaultValidator = stealthAddressValidator;
        _setAddress();
        _setExecutionDetail();
    }

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
        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);
        return abi.encodeWithSelector(
            KernelStorage.initialize.selector,
            defaultValidator,
            abi.encodePacked(
                stealthAddressKey.stealthAddress,
                stealthAddressKey.stealthPub,
                stealthAddressKey.dhPub,
                stealthAddressKey.stealthPrefix,
                stealthAddressKey.dhPrefix,
                stealthAddressKey.ephemeralPub,
                stealthAddressKey.ephemeralPrefix
            )
        );
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);
        return abi.encodePacked(
            bytes4(0x00000000), bytes1(0x00), _generateUserOpSignature(entryPoint, op, stealthAddressKey.stealthPrivate)
        );
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);
        return abi.encodePacked(
            bytes4(0x00000000),
            bytes1(0x00),
            _generateUserOpSignature(entryPoint, op, stealthAddressKey.stealthPrivate + 1)
        );
    }

    function signHash(bytes32 _hash) internal view override returns (bytes memory) {
        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);
        return _generateHashSignature(_hash, address(kernel), stealthAddressKey.stealthPrivate);
    }

    function getWrongSignature(bytes32 _hash) internal view override returns (bytes memory) {
        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);
        return _generateHashSignature(_hash, address(kernel), stealthAddressKey.stealthPrivate + 1);
    }

    function test_default_validator_enable() external override {
        StealthAddressKey memory stealthAddressKey = getStealthAddress(wallet, ephemeralWallet);

        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(
                    StealthAddressValidator.enable.selector,
                    abi.encodePacked(
                        stealthAddressKey.stealthAddress,
                        stealthAddressKey.stealthPub,
                        stealthAddressKey.dhPub,
                        stealthAddressKey.stealthPrefix,
                        stealthAddressKey.dhPrefix,
                        stealthAddressKey.ephemeralPub,
                        stealthAddressKey.ephemeralPrefix
                    )
                ),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        address owner = stealthAddressValidator.getOwner(address(kernel));
        assertEq(owner, stealthAddressKey.stealthAddress, "owner should be stealthAddress");
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(StealthAddressValidator.disable.selector, ""),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
        address owner = stealthAddressValidator.getOwner(address(kernel));
        assertEq(owner, address(0), "owner should be 0");
    }

    function test_stealth_validate_userop_aggsig() external {
        UserOperation memory userOp = UserOperation({
            sender: address(kernel),
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Get the validator domain separator
        bytes32 domainSeparator = stealthAddressValidator.getDomainSeperator();
        bytes32 typedMsgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator, keccak256(abi.encode(USER_OP_TYPEHASH, owner, address(kernel), userOpHash))
            )
        );
        bytes memory aggregatedSignature = getAggregatedSignature(typedMsgHash, wallet);
        userOp.signature = aggregatedSignature;

        (,, address result) = parseValidationData(defaultValidator.validateUserOp(userOp, userOpHash, 0));
        assertEq(result, address(0));
    }

    function test_stealth_validate_sig_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));

        // Get the validator domain separator
        bytes32 domainSeparator = stealthAddressValidator.getDomainSeperator();
        bytes32 typedMsgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator, keccak256(abi.encode(SIGNATURE_TYPEHASH, owner, address(kernel), message))
            )
        );
        bytes memory aggregatedSignature = getAggregatedSignature(typedMsgHash, wallet);

        vm.prank(address(kernel));
        (,, address result) = parseValidationData(defaultValidator.validateSignature(message, aggregatedSignature));
        assertEq(result, address(0));
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
        address owner = vm.addr(_privateKey);

        // Get the user op hash
        bytes32 userOpHash = _entryPoint.getUserOpHash(_op);
        // Get the validator domain separator
        bytes32 domainSeparator = stealthAddressValidator.getDomainSeperator();
        bytes32 typedMsgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator, keccak256(abi.encode(USER_OP_TYPEHASH, owner, _op.sender, userOpHash))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, typedMsgHash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice The type hash used for kernel signature validation
    bytes32 constant SIGNATURE_TYPEHASH = keccak256("KernelSignature(address owner,address kernelWallet,bytes32 hash)");

    /// @dev Generate the signature for a given hash for a kernel account
    function _generateHashSignature(bytes32 _hash, address _kernel, uint256 _privateKey)
        internal
        view
        returns (bytes memory)
    {
        // Get the kernel private key owner address
        address owner = vm.addr(_privateKey);

        // Get the validator domain separator
        bytes32 domainSeparator = stealthAddressValidator.getDomainSeperator();
        bytes32 typedMsgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator, keccak256(abi.encode(SIGNATURE_TYPEHASH, owner, _kernel, _hash))
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, typedMsgHash);
        return abi.encodePacked(bytes1(0), r, s, v);
    }

    /// @notice The parameter used in the elliptic curve
    uint256 GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 AA = 0;
    uint256 PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    /// @dev Generate stealth address
    function getStealthAddress(VmSafe.Wallet memory _ownerWallet, VmSafe.Wallet memory _ephemeralWallet)
        public
        view
        returns (StealthAddressKey memory)
    {
        (uint256 ephemeralPub, uint256 ephemeralPrefix) =
            (_ephemeralWallet.publicKeyX, _ephemeralWallet.publicKeyY % 2 + 2);

        (uint256 sharedSecretX, uint256 sharedSecretY) =
            EllipticCurve.ecMul(_ephemeralWallet.privateKey, _ownerWallet.publicKeyX, _ownerWallet.publicKeyY, AA, PP);
        uint256 hashSecret = uint256(keccak256(abi.encode(sharedSecretX, sharedSecretY)));
        (uint256 pubX, uint256 pubY) = EllipticCurve.ecMul(hashSecret, GX, GY, AA, PP);
        uint256 stealthPrivate = _ownerWallet.privateKey + hashSecret % N;
        (uint256 stealthPubX, uint256 stealthPubY) =
            EllipticCurve.ecAdd(_ownerWallet.publicKeyX, _ownerWallet.publicKeyY, pubX, pubY, AA, PP);
        address stealthAddress = address(uint160(uint256(keccak256(abi.encode(stealthPubX, stealthPubY)))));
        (uint256 dhkx, uint256 dhky) =
            EllipticCurve.ecMul(hashSecret, _ownerWallet.publicKeyX, _ownerWallet.publicKeyY, AA, PP);
        return StealthAddressKey(
            stealthAddress,
            stealthPubX,
            dhkx,
            uint8(stealthPubY % 2 + 2),
            uint8(dhky % 2 + 2),
            ephemeralPub,
            uint8(ephemeralPrefix),
            hashSecret,
            stealthPrivate
        );
    }

    function getAggregatedSignature(bytes32 _hash, Vm.Wallet memory _wallet) internal view returns (bytes memory) {
        StealthAddressKey memory stelathAddressKey = getStealthAddress(_wallet, ephemeralWallet);
        (, bytes32 r, bytes32 s) = vm.sign(_wallet.privateKey, _hash);
        uint256 numR = uint256(r);
        uint256 numS = uint256(s);

        // aggregatedSig = numS * (stelathAddressKey.hashSecret * numR + typedMsgHash)
        bytes32 aggregatedSig = bytes32(
            FixedPointMathLib.rawMulMod(
                FixedPointMathLib.rawAddMod(
                    FixedPointMathLib.rawMulMod(stelathAddressKey.hashSecret, numR, N), uint256(_hash), N
                ),
                numS,
                N
            )
        );

        return abi.encodePacked(bytes1(uint8(1)), r, aggregatedSig);
    }
}
