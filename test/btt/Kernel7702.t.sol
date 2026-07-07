// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";
import {InvalidValidationType} from "src/types/Error.sol";
import {Received} from "src/types/Events.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";

/// @title Kernel7702 BTT Tests
/// @notice Tests for Kernel7702 variant following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel7702.tree
contract Kernel7702_Test is Test {
    IEntryPoint ep;
    KernelFactory factory;
    Kernel7702 template;
    Kernel kernel;

    address owner;
    uint256 ownerKey;

    MockValidator newValidator;

    function setUp() public {
        ep = EntryPointLib.deploy();

        template = new Kernel7702(ep);
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);

        (owner, ownerKey) = makeAddrAndKey("Owner");
        kernel = Kernel(payable(owner));
        // EIP-7702: etch the delegation designator onto the owner EOA
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(template)));
        vm.deal(owner, 100 ether);

        newValidator = new MockValidator();
        newValidator.sudoSetSuccess(true);
    }

    /*//////////////////////////////////////////////////////////////
                        INITIALIZE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenInitializeIsCalledWithPackages() external {
        // it should not install any packages
        // it should not revert
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        // Kernel7702.initialize is a NO-OP, should not revert
        kernel.initialize(packages);

        // Verify nothing was installed since initialize is a no-op
        assertFalse(
            kernel.isModuleInstalled(1, address(newValidator), ""),
            "Validator should NOT be installed after no-op initialize"
        );
    }

    function test_WhenInitializeIsCalledMultipleTimes() external {
        // it should not revert on any call
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        // Call multiple times - should never revert since it's a no-op
        kernel.initialize(packages);
        kernel.initialize(packages);
        kernel.initialize(packages);

        // Still nothing installed
        assertFalse(
            kernel.isModuleInstalled(1, address(newValidator), ""),
            "Validator should NOT be installed after multiple no-op calls"
        );

        // Also works with empty packages
        Install[] memory empty = new Install[](0);
        kernel.initialize(empty);
    }

    function test_WhenInitializeIsCalledWithEmptyPackages() external {
        // it should not revert
        Install[] memory empty = new Install[](0);
        kernel.initialize(empty);
    }

    /*//////////////////////////////////////////////////////////////
                    _verifyFallbackSignature TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenVerifyFallbackSignatureReceivesAValidECDSASignature() external {
        // it should return validation success
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = _signHash(ownerKey, opHash);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 0, "Valid fallback signature should return success");
    }

    function test_WhenVerifyFallbackSignatureReceivesAnInvalidECDSASignature() external {
        // it should return validation failed
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);

        (, uint256 wrongKey) = makeAddrAndKey("WrongSigner");
        op.signature = _signHash(wrongKey, opHash);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1, "Invalid fallback signature should return failure");
    }

    function test_WhenVerifyFallbackSignatureReceivesAMalformedSignature() external {
        // it should return validation failed
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = hex"deadbeef"; // malformed: too short for ECDSA

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1, "Malformed signature should return failure");
    }

    function test_WhenVerifyFallbackSignatureReceivesAZeroLengthSignature() external {
        // it should return validation failed
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = hex""; // zero length

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1, "Zero-length signature should return failure");
    }

    /*//////////////////////////////////////////////////////////////
                _fallbackValidatorAvailable TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenFallbackValidatorAvailableIsChecked() external {
        // it should return true
        // Prove _fallbackValidatorAvailable returns true by showing that
        // validateUserOp with root=bytes21(0) works (uses fallback path)
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = _signHash(ownerKey, opHash);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 0, "Fallback validator should be available");
    }

    /*//////////////////////////////////////////////////////////////
                _erc1271RawAllowed TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenErc1271RawAllowedIsChecked() external {
        // it should return true allowing raw signatures
        // Kernel7702 has _erc1271RawAllowed() = true. Prove it by showing
        // that a raw ECDSA signature (without ERC-7739 wrapping) is accepted
        bytes32 hash = keccak256("test raw allowed");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);

        bytes4 result = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(result, ERC1271_MAGICVALUE, "Raw ECDSA should be valid when _erc1271RawAllowed is true");
    }

    /*//////////////////////////////////////////////////////////////
                    isValidSignature RAW PATH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenIsValidSignatureReceivesAValidRawECDSASignature() external {
        // it should return ERC1271_MAGICVALUE
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);

        bytes4 result = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(result, ERC1271_MAGICVALUE, "Valid raw ECDSA should return MAGICVALUE");
    }

    function test_WhenIsValidSignatureReceivesAnInvalidRawECDSASignature() external {
        // it should revert because fallthrough parses invalid validation type
        bytes32 hash = keccak256("test_invalid_signature");
        (, uint256 wrongKey) = makeAddrAndKey("WrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);

        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
    }

    /*//////////////////////////////////////////////////////////////
                validateUserOp WITH ROOT ZERO TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenValidateUserOpIsCalledWithRootZeroAndValidECDSASignature() external {
        // it should return zero for validation success
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = _signHash(ownerKey, opHash);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 0, "Root zero with valid ECDSA should return 0");
    }

    function test_WhenValidateUserOpIsCalledWithRootZeroAndWrongSigner() external {
        // it should return one for validation failure
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);

        (, uint256 wrongKey) = makeAddrAndKey("WrongSigner");
        op.signature = _signHash(wrongKey, opHash);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1, "Root zero with wrong signer should return 1");
    }

    function test_WhenValidateUserOpIsCalledWithRootZeroAndMalformedSignature() external {
        // it should return one for validation failure
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = hex"deadbeef";

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1, "Root zero with malformed sig should return 1");
    }

    /*//////////////////////////////////////////////////////////////
                validateUserOp WITH missingAccountFunds TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenValidateUserOpIsCalledWithMissingAccountFundsNonzero() external {
        // it should send funds to the entry point
        PackedUserOperation memory op = _buildUserOp();
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = _signHash(ownerKey, opHash);

        uint256 epBalanceBefore = address(ep).balance;
        uint256 missingFunds = 0.01 ether;

        vm.prank(address(ep));
        kernel.validateUserOp(op, opHash, missingFunds);

        assertEq(address(ep).balance, epBalanceBefore + missingFunds, "Entry point should receive missingAccountFunds");
    }

    /*//////////////////////////////////////////////////////////////
                installModule VIA DIRECT CALL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenAValidatorIsInstalledViaDirectInstallModule() external {
        // it should allow validation with the installed validator
        // Even though initialize is a no-op, modules can be installed directly
        vm.prank(address(ep));
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));

        assertTrue(
            kernel.isModuleInstalled(1, address(newValidator), ""),
            "Validator should be installed via direct installModule"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    RECEIVE ETH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenTheEOAReceivesETH() external {
        // it should emit Received event
        address sender = makeAddr("sender");
        vm.deal(sender, 1 ether);

        vm.prank(sender);
        vm.expectEmit(true, true, true, true, address(kernel));
        emit Received(sender, 0.5 ether);
        (bool success,) = address(kernel).call{value: 0.5 ether}("");
        assertTrue(success, "ETH transfer should succeed");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _buildUserOp() internal view returns (PackedUserOperation memory op) {
        op.sender = address(kernel);
        // nonce with ROOT validation type (0x00) and zero vId
        op.nonce = _encodeNonce(bytes1(0), bytes20(0));
        op.callData = abi.encodeWithSelector(kernel.execute.selector, bytes32(0), "");
        op.accountGasLimits = bytes32(uint256(100000) << 128 | uint256(100000));
        op.preVerificationGas = 100000;
        op.gasFees = bytes32(uint256(1) << 128 | uint256(1));
    }

    function _encodeNonce(bytes1 vType, bytes20 vId) internal view returns (uint256 nonce) {
        uint192 key = uint192(bytes24(abi.encodePacked(uint8(0), vType, vId, bytes2(0x00))));
        return ep.getNonce(address(kernel), key);
    }

    function _signHash(uint256 privateKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }
}
