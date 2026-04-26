// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LibString} from "solady/utils/LibString.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";
import {BTTModifiers} from "./BTTModifiers.sol";
import {Install} from "src/types/Structs.sol";
import {Kernel} from "src/Kernel.sol";
import {
    InvalidValidationType,
    InvalidValidator,
    InvalidPermissionId,
    InvalidNonce,
    InvalidVid
} from "src/types/Error.sol";
import {ValidationId, validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {PermissionId} from "src/types/Types.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @title Kernel.isValidSignature BTT Tests
/// @notice Tests for isValidSignature following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.isValidSignature.tree
abstract contract Kernel_isValidSignature is BTTModifiers {
    // State variables for isValidSignature branch tracking
    // Note: _validationType and _isTypedDataSign are inherited from BTTModifiers
    bytes32 internal _testHash;
    bool internal _enableMode;
    bool internal _isExplicitContentsName;
    bool internal _isReplayableSignature;

    function test_WhenHashEqualsERC7739_MAGIC_HASH() external {
        // it should return ERC7739 support indicator
        bytes4 result = kernel.isValidSignature(ERC7739_MAGIC_HASH, "");
        assertEq(result, bytes4(0x77390001), "Should return ERC7739 support indicator");
    }

    modifier whenHashIsNotERC7739_MAGIC_HASH() {
        _testHash = keccak256("test"); // Set non-magic hash
        _;
    }

    modifier givenTheSignatureModeByteIndicatesEnableMode() {
        _enableMode = true;
        _;
    }

    function test_GivenTheValidationTypeIsROOT()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
    {
        // it should revert with InvalidValidationType error
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        // ROOT validation type (0x00) is not allowed with enable mode
        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x00), // ROOT validation type
            bytes20(0), // No validator address for root
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
    }

    function test_GivenTheEnableNonceIsInvalid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
    {
        // it should revert with InvalidNonce error
        // Note: isValidSignature is a view function, so nonces are validated but not consumed.
        // To test invalid nonce, we use nonce 1 when stored nonce is 0 (invalid because seq != stored).
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        // Use nonce 1 when stored nonce is 0 - this is invalid
        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(1), packages, enableSig(1, true, false, packages, _rootSignHash), sig)
        );

        vm.expectRevert(InvalidNonce.selector);
        kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
    }

    function test_GivenTheEnableSignatureIsInvalid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
    {
        // it should return ERC1271_INVALID
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        // Use invalid root signature for enable
        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, false, false, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
        assertEq(res, ERC1271_INVALID, "Enable mode with invalid signature should return INVALID");
    }

    modifier givenTheEnableSignatureIsValid() {
        require(_enableMode, "Enable mode should be set");
        _;
    }

    function test_GivenTheEnableSignatureIsValid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
    {
        // it should install the packages from the signature
        // it should continue with the remaining signature validation
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
        assertEq(res, ERC1271_MAGICVALUE, "Enable mode with valid signature should return MAGICVALUE");
    }

    function test_GivenTheValidatorPackageIsMissing()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
        givenTheEnableSignatureIsValid
    {
        // it should revert with InvalidValidator error
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        // Create packages that don't include the validator specified in the signature
        MockValidator wrongValidator = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(wrongValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        // The signature specifies newValidator but packages install wrongValidator
        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator, // This validator is NOT in the packages
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        vm.expectRevert(InvalidValidator.selector);
        kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
    }

    function test_GivenThePermissionSignaturesAreInconsistent()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
        givenTheEnableSignatureIsValid
    {
        // it should revert with InvalidPermissionId error
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, true);

        // Create packages with inconsistent permissionIds
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId permId1 = PermissionId.wrap(bytes4(keccak256("permId1")));
        PermissionId permId2 = PermissionId.wrap(bytes4(keccak256("permId2"))); // Different!

        // Set up the mock policy to pass validation so we can reach the permissionId consistency check
        mockPolicy.sudoSetPass(address(kernel), bytes32(PermissionId.unwrap(permId1)), true);

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5, module: address(mockPolicy), moduleData: hex"", internalData: abi.encodePacked(permId1)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(mockSigner),
            moduleData: hex"",
            internalData: abi.encodePacked(permId2) // Different permissionId!
        });

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x02), // PERMISSION validation type
            permId1,
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        vm.expectRevert(InvalidPermissionId.selector);
        kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
    }

    function test_GivenEnableModeIsReplayable()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
    {
        // it should verify the enable signature without chainId
        // it should allow cross-chain enable mode
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag
        uMode += 2 ** 2; // replayable flag

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, true, true, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
        assertEq(res, ERC1271_MAGICVALUE, "Replayable enable mode should validate");
    }

    function test_GivenEnableModeIsNotReplayable()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureModeByteIndicatesEnableMode
    {
        // it should verify the enable signature with chainId
        // it should fail on different chains
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag
        // NOT replayable (no replayable flag)

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
        assertEq(res, ERC1271_MAGICVALUE, "Non-replayable enable mode should validate on same chain");
    }

    modifier givenTheValidationTypeIsROOT() {
        _validationType = 0;
        _;
    }

    modifier givenTheSignatureFormatIsTypedDataSign() {
        _isTypedDataSign = true;
        _;
    }

    function test_WhenTheRootValidatorReturnsValid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsROOT
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_MAGICVALUE
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Valid root signature should return MAGICVALUE");
    }

    function test_WhenTheRootValidatorReturnsInvalid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsROOT
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_INVALID
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID, "Invalid root signature should return INVALID");
    }

    modifier givenTheSignatureFormatIsPersonalSign() {
        _isTypedDataSign = false;
        _;
    }

    function test_GivenTheSignatureFormatIsPersonalSign()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsROOT
        givenTheSignatureFormatIsPersonalSign
    {
        // it should wrap the hash with PersonalSign struct
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "PersonalSign should wrap hash and validate");
    }

    function test_WhenTheRootValidatorReturnsValid_GivenTheSignatureFormatIsPersonalSign()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsROOT
        givenTheSignatureFormatIsPersonalSign
    {
        // it should return ERC1271_MAGICVALUE
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Valid root PersonalSign should return MAGICVALUE");
    }

    function test_WhenTheRootValidatorReturnsInvalid_GivenTheSignatureFormatIsPersonalSign()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsROOT
        givenTheSignatureFormatIsPersonalSign
    {
        // it should return ERC1271_INVALID
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, false);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID, "Invalid root PersonalSign should return INVALID");
    }

    function test_GivenTheSignatureIncludesDomainSeparatorAndContents()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsROOT
    {
        // it should verify the full TypedDataSign structure
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Full TypedDataSign structure should validate");
    }

    modifier givenTheValidationTypeIsVALIDATOR() {
        _validationType = 1;
        _;
    }

    function test_WhenTheValidatorReturnsValid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsVALIDATOR
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_MAGICVALUE
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));

        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE, "Valid validator signature should return MAGICVALUE");
    }

    function test_WhenTheValidatorReturnsInvalid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsVALIDATOR
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_INVALID
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));

        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_INVALID, "Invalid validator signature should return INVALID");
    }

    function test_WhenTheValidatorReturnsValid_GivenTheSignatureFormatIsPersonalSign()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsVALIDATOR
        givenTheSignatureFormatIsPersonalSign
    {
        // it should return ERC1271_MAGICVALUE
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));

        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(
            messageHash, abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE, "Valid validator PersonalSign should return MAGICVALUE");
    }

    function test_WhenTheValidatorReturnsInvalid_GivenTheSignatureFormatIsPersonalSign()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsVALIDATOR
        givenTheSignatureFormatIsPersonalSign
    {
        // it should return ERC1271_INVALID
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));

        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, false);

        bytes4 ret = kernel.isValidSignature(
            messageHash, abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_INVALID, "Invalid validator PersonalSign should return INVALID");
    }

    modifier givenTheValidationTypeIsPERMISSION() {
        _validationType = 2;
        _;
    }

    function test_WhenAllPoliciesPassAndSignerReturnsValid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsPERMISSION
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_MAGICVALUE
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, true);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE, "Valid permission should return MAGICVALUE");
    }

    function test_WhenAnyPolicyFails()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsPERMISSION
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_INVALID
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        bytes32 messageHash = keccak256("Hello world");
        permissionRevertIndex = 0; // policy fails
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );
        assertEq(ret, ERC1271_INVALID, "Failed policy should return INVALID");
    }

    function test_WhenSignerReturnsInvalid()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsPERMISSION
        givenTheSignatureFormatIsTypedDataSign
    {
        // it should return ERC1271_INVALID
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        bytes32 messageHash = keccak256("Hello world");
        permissionRevertIndex = 1; // signer fails
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );
        assertEq(ret, ERC1271_INVALID, "Invalid signer should return INVALID");
    }

    function test_WhenAllPoliciesPassAndSignerReturnsValid_GivenTheSignatureFormatIsPersonalSign()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsPERMISSION
        givenTheSignatureFormatIsPersonalSign
    {
        // it should return ERC1271_MAGICVALUE
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Valid permission PersonalSign should return MAGICVALUE");
    }

    function test_WhenAnyPolicyOrSignerFails()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheValidationTypeIsPERMISSION
        givenTheSignatureFormatIsPersonalSign
    {
        // it should return ERC1271_INVALID
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        permissionRevertIndex = 0; // policy fails
        bytes memory sig = _permissionSignHash(personalHash, false);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig));
        assertEq(ret, ERC1271_INVALID, "Failed policy/signer should return INVALID");
    }

    function test_GivenTheValidationTypeIsUnsupported() external whenHashIsNotERC7739_MAGIC_HASH {
        // it should revert with InvalidValidationType error
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, true);

        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0xee), permissionId, sig));
    }

    function test_GivenTheSignatureIsWrappedWithERC6492Sentinel() external whenHashIsNotERC7739_MAGIC_HASH {
        // it should unwrap and validate the inner signature
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory innerSig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);

        bytes memory fullInnerSig = abi.encodePacked(bytes1(0), bytes1(0), innerSig);

        // Wrap with ERC6492 sentinel: abi.encode(address, bytes, bytes) ++ sentinel
        // The sentinel is 0x6492...6492
        bytes32 sentinel = 0x6492649264926492649264926492649264926492649264926492649264926492;
        bytes memory wrappedSig = abi.encodePacked(
            abi.encode(
                address(0xdead), // factory address (unused for already-deployed)
                hex"", // factory calldata (unused)
                fullInnerSig // actual signature
            ),
            sentinel
        );

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), wrappedSig);
        assertEq(ret, ERC1271_MAGICVALUE, "ERC6492 wrapped signature should validate after unwrapping");
    }

    modifier givenTheSignatureFormatIsTypedDataSignWithExplicitContentsName() {
        _isExplicitContentsName = true;
        _;
    }

    function test_WhenTheRootValidatorReturnsValid_GivenTheSignatureFormatIsTypedDataSignWithExplicitContentsName()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureFormatIsTypedDataSignWithExplicitContentsName
    {
        // it should return ERC1271_MAGICVALUE
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "MyContents", _rootSignHash, true, true);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Valid explicit contentsName should return MAGICVALUE");
    }

    function test_WhenTheRootValidatorReturnsInvalid_GivenTheSignatureFormatIsTypedDataSignWithExplicitContentsName()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureFormatIsTypedDataSignWithExplicitContentsName
    {
        // it should return ERC1271_INVALID
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "MyContents", _rootSignHash, true, false);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID, "Invalid explicit contentsName should return INVALID");
    }

    modifier givenTheSignatureFormatIsReplayableTypedDataSignWithExplicitContentsName() {
        _isExplicitContentsName = true;
        _isReplayableSignature = true;
        _;
    }

    function test_WhenTheRootValidatorReturnsValid_GivenTheSignatureFormatIsReplayableTypedDataSignWithExplicitContentsName()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureFormatIsReplayableTypedDataSignWithExplicitContentsName
    {
        // it should return ERC1271_MAGICVALUE
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271SignatureReplayableExplicit(messageHash, "C(bytes32 stuff)", "MyContents", _rootSignHash, true);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Valid replayable explicit contentsName should return MAGICVALUE");
    }

    function test_WhenTheRootValidatorReturnsInvalid_GivenTheSignatureFormatIsReplayableTypedDataSignWithExplicitContentsName()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureFormatIsReplayableTypedDataSignWithExplicitContentsName
    {
        // it should return ERC1271_INVALID
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271SignatureReplayableExplicit(messageHash, "C(bytes32 stuff)", "MyContents", _rootSignHash, false);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID, "Invalid replayable explicit contentsName should return INVALID");
    }

    function test_GivenTheRootValidationIsNotSet() external whenHashIsNotERC7739_MAGIC_HASH {
        // it should return ERC1271_INVALID via base fallback signature
        // Deploy an uninitialized kernel proxy (no root set, so root == bytes21(0))
        address uninitProxy = LibClone.deployERC1967(address(factory.UUPS()));
        Kernel uninit = Kernel(payable(uninitProxy));

        bytes32 messageHash = keccak256("Hello world");
        // Signature won't match TypedDataSign reconstruction, falls to PersonalSign.
        // PersonalSign wraps hash and calls _erc1271IsValidSignatureNowCalldata.
        // ROOT type with root=0 triggers _verifyFallbackSignature -> returns false.
        bytes4 ret = uninit.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), bytes32(0)));
        assertEq(ret, ERC1271_INVALID, "Uninitialized kernel should return INVALID via fallback");
    }

    modifier givenTheSignatureFormatIsReplayableTypedDataSign() {
        _isReplayableSignature = true;
        _;
    }

    function test_WhenTheRootValidatorReturnsValidForReplayable()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureFormatIsReplayableTypedDataSign
    {
        // it should return ERC1271_MAGICVALUE
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271SignatureReplayable(messageHash, "C(bytes32 stuff)", _rootSignHash, true);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE, "Valid replayable TypedDataSign should return MAGICVALUE");
    }

    function test_WhenTheRootValidatorReturnsInvalidForReplayable()
        external
        whenHashIsNotERC7739_MAGIC_HASH
        givenTheSignatureFormatIsReplayableTypedDataSign
    {
        // it should return ERC1271_INVALID
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271SignatureReplayable(messageHash, "C(bytes32 stuff)", _rootSignHash, false);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID, "Invalid replayable TypedDataSign should return INVALID");
    }
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant ERC7739_MAGIC_HASH = 0x7739773977397739773977397739773977397739773977397739773977397739;
    bytes32 internal constant _DOMAIN_SEP_B = 0xa1a044077d7677adbbfa892ded5390979b33993e0e2a457e3f974bbcda53821b;

    /*//////////////////////////////////////////////////////////////
                        ERC7739 MAGIC HASH TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should return 0x77390001 (ERC7739 support indicator)
    function test_WhenHashIsERC7739MagicHash() external unitTest givenHashIsERC7739MagicHash {
        bytes4 result = kernel.isValidSignature(ERC7739_MAGIC_HASH, "");

        assertEq(result, bytes4(0x77390001), "Should return ERC7739 support indicator");
    }

    /*//////////////////////////////////////////////////////////////
                        ROOT VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should return ERC1271_MAGICVALUE when root validator returns valid (TypedDataSign)
    function test_WhenRootValidatorReturnsValid_TypedDataSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsRoot
        givenSignatureFormatIsTypedDataSign
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));

        assertEq(ret, ERC1271_MAGICVALUE, "Valid root signature should return MAGICVALUE");
    }

    /// @notice it should return ERC1271_INVALID when root validator returns invalid (TypedDataSign)
    function test_WhenRootValidatorReturnsInvalid_TypedDataSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsRoot
        givenSignatureFormatIsTypedDataSign
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));

        assertEq(ret, ERC1271_INVALID, "Invalid root signature should return INVALID");
    }

    /// @notice it should return ERC1271_MAGICVALUE when root validator returns valid (PersonalSign)
    function test_WhenRootValidatorReturnsValid_PersonalSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsRoot
        givenSignatureFormatIsPersonalSign
    {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));

        assertEq(ret, ERC1271_MAGICVALUE, "Valid root PersonalSign should return MAGICVALUE");
    }

    /// @notice it should return ERC1271_INVALID when root validator returns invalid (PersonalSign)
    function test_WhenRootValidatorReturnsInvalid_PersonalSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsRoot
        givenSignatureFormatIsPersonalSign
    {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, false);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));

        assertEq(ret, ERC1271_INVALID, "Invalid root PersonalSign should return INVALID");
    }

    /*//////////////////////////////////////////////////////////////
                        VALIDATOR VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Unlike validateUserOp, isValidSignature does NOT revert for uninstalled validators
    /// It directly calls the validator and returns its result
    function test_isValidSignature_WhenValidatorNotInstalled_RevertsWithInvalidVid()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsValidator
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        // The kernel checks if the validator is installed before calling it
        // If not installed, it reverts with InvalidVid
        ValidationId vId = validatorToIdentifier(IValidator(address(newValidator)));
        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, vId));
        kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
    }

    /// @notice it should return ERC1271_MAGICVALUE when validator returns valid (TypedDataSign)
    function test_WhenValidatorReturnsValid_TypedDataSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsValidator
        givenValidatorIsInstalled
        givenSignatureFormatIsTypedDataSign
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );

        assertEq(ret, ERC1271_MAGICVALUE, "Valid validator signature should return MAGICVALUE");
    }

    /// @notice it should return ERC1271_INVALID when validator returns invalid (TypedDataSign)
    function test_WhenValidatorReturnsInvalid_TypedDataSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsValidator
        givenValidatorIsInstalled
        givenSignatureFormatIsTypedDataSign
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );

        assertEq(ret, ERC1271_INVALID, "Invalid validator signature should return INVALID");
    }

    /// @notice it should return ERC1271_MAGICVALUE when validator returns valid (PersonalSign)
    function test_WhenValidatorReturnsValid_PersonalSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsValidator
        givenValidatorIsInstalled
        givenSignatureFormatIsPersonalSign
    {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(
            messageHash, abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );

        assertEq(ret, ERC1271_MAGICVALUE, "Valid validator PersonalSign should return MAGICVALUE");
    }

    /*//////////////////////////////////////////////////////////////
                        PERMISSION VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert with InvalidPermissionId when permission is not installed
    function test_isValidSignature_RevertWhen_PermissionNotInstalled()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsPermission
    {
        // it should revert with InvalidVid error when permission is not installed
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, true);

        ValidationId vId = permissionToIdentifier(permissionId);
        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, vId));
        kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );
    }

    /// @notice it should return ERC1271_INVALID when any policy fails
    function test_isValidSignature_WhenPermissionPolicyFails()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsPermission
        givenPermissionIsInstalled
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, false);

        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );

        assertEq(ret, ERC1271_INVALID, "Failed policy should return INVALID");
    }

    /// @notice it should return ERC1271_MAGICVALUE when permission valid (PersonalSign)
    function test_WhenPermissionValid_PersonalSign()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenValidationTypeIsPermission
        givenPermissionIsInstalled
        givenSignatureFormatIsPersonalSign
    {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, true);

        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig));

        assertEq(ret, ERC1271_MAGICVALUE, "Valid permission PersonalSign should return MAGICVALUE");
    }

    /*//////////////////////////////////////////////////////////////
                    INVALID VALIDATION TYPE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert with InvalidValidationType when type is unsupported
    function test_RevertWhen_InvalidValidationType() external unitTest givenHashIsNotERC7739MagicHash {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, true);

        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0xee), permissionId, sig));
    }

    /*//////////////////////////////////////////////////////////////
                        ENABLE MODE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should install packages and validate when enable mode signature is valid
    function test_isValidSignature_WhenEnableModeWithValidSignature()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenSignatureModeIndicatesEnableMode
        givenValidationTypeIsValidator
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);

        assertEq(res, ERC1271_MAGICVALUE, "Enable mode with valid signature should return MAGICVALUE");
    }

    /// @notice it should return ERC1271_INVALID when enable mode signature is invalid
    function test_isValidSignature_WhenEnableModeWithInvalidSignature()
        external
        unitTest
        givenHashIsNotERC7739MagicHash
        givenSignatureModeIndicatesEnableMode
        givenValidationTypeIsValidator
    {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, false);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, true, false, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);

        assertEq(res, ERC1271_INVALID, "Enable mode with invalid signature should return INVALID");
    }

    /*//////////////////////////////////////////////////////////////
                        REPLAYABLE MODE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should allow cross-chain enable mode with replayable signature
    function test_WhenEnableModeReplayable_CrossChainValid() external unitTest givenHashIsNotERC7739MagicHash {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        uint8 uMode = 0;
        uMode += 2 ** 3; // enable mode flag
        uMode += 2 ** 2; // replayable flag

        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(uint256(0), packages, enableSig(0, true, true, packages, _rootSignHash), sig)
        );

        bytes4 res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
        assertEq(res, ERC1271_MAGICVALUE, "Replayable enable mode should validate");

        // Simulate different chain by changing chainId (if not mock)
        if (!isMock) {
            vm.chainId(1000);
            res = kernel.isValidSignature(_toContentsHash(contentsHash), sigWithEnable);
            assertEq(res, ERC1271_MAGICVALUE, "Replayable should work on different chain");
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _toContentsHash(bytes32 contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _DOMAIN_SEP_B, contents));
    }

    function _erc1271Signature(
        bytes32 hash,
        bytes memory contentsType,
        bytes memory contentsName,
        function(bytes32, bool) returns (bytes memory) signFn,
        bool isExplicit,
        bool success
    ) internal returns (bytes32 contentsHash, bytes memory sig) {
        contentsHash = keccak256(abi.encode(hash, contentsType));
        bytes32 actualHash;
        if (isExplicit) {
            actualHash = _toErc1271Hash(address(kernel), contentsHash, contentsType, contentsName);
        } else {
            actualHash = _toErc1271Hash(address(kernel), contentsHash, contentsType, _contentsName(contentsType));
        }
        sig = signFn(actualHash, success);
        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName);
        sig =
            abi.encodePacked(sig, _DOMAIN_SEP_B, contentsHash, contentsDescription, uint16(contentsDescription.length));
    }

    function _toErc1271Hash(address account, bytes32 contents, bytes memory contentsType, bytes memory contentsName)
        internal
        view
        returns (bytes32)
    {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(_typedDataSignTypeHash(contentsType, contentsName), contents),
                _accountDomainStructFields(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEP_B, parentStructHash));
    }

    function _accountDomainStructFields(address account) internal view returns (bytes memory) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            Kernel(payable(account)).eip712Domain();
        return abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
    }

    function _toErc1271HashPersonalSign(bytes32 childHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            kernel.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(abi.encodePacked(name)),
                keccak256(abi.encodePacked(version)),
                chainId,
                verifyingContract
            )
        );
        bytes32 parentStructHash = keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), childHash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, parentStructHash));
    }

    function _typedDataSignTypeHash(bytes memory contentsType, bytes memory contentsName)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
    }

    function _contentsName(bytes memory contentsType) internal pure returns (bytes memory) {
        string memory ct = string(contentsType);
        return bytes(LibString.slice(ct, 0, LibString.indexOf(ct, "(", 0)));
    }

    /// @dev Creates a replayable TypedDataSign signature (without chainId in the struct)
    function _erc1271SignatureReplayable(
        bytes32 hash,
        bytes memory contentsType,
        function(bytes32, bool) returns (bytes memory) signFn,
        bool success
    ) internal returns (bytes32 contentsHash, bytes memory sig) {
        contentsHash = keccak256(abi.encode(hash, contentsType));
        bytes memory contentsName = _contentsName(contentsType);
        bytes32 actualHash = _toErc1271HashReplayable(address(kernel), contentsHash, contentsType, contentsName);
        sig = signFn(actualHash, success);
        bytes memory contentsDescription = abi.encodePacked(contentsType);
        sig =
            abi.encodePacked(sig, _DOMAIN_SEP_B, contentsHash, contentsDescription, uint16(contentsDescription.length));
    }

    /// @dev Creates a replayable TypedDataSign signature with explicit contentsName
    function _erc1271SignatureReplayableExplicit(
        bytes32 hash,
        bytes memory contentsType,
        bytes memory contentsName,
        function(bytes32, bool) returns (bytes memory) signFn,
        bool success
    ) internal returns (bytes32 contentsHash, bytes memory sig) {
        contentsHash = keccak256(abi.encode(hash, contentsType));
        bytes32 actualHash = _toErc1271HashReplayable(address(kernel), contentsHash, contentsType, contentsName);
        sig = signFn(actualHash, success);
        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName);
        sig =
            abi.encodePacked(sig, _DOMAIN_SEP_B, contentsHash, contentsDescription, uint16(contentsDescription.length));
    }

    /// @dev Computes the replayable EIP-712 hash (without chainId)
    function _toErc1271HashReplayable(
        address account,
        bytes32 contents,
        bytes memory contentsType,
        bytes memory contentsName
    ) internal view returns (bytes32) {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(_typedDataSignTypeHashReplayable(contentsType, contentsName), contents),
                _accountDomainStructFieldsReplayable(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEP_B, parentStructHash));
    }

    /// @dev Account domain struct fields without chainId for replayable mode
    function _accountDomainStructFieldsReplayable(address account) internal view returns (bytes memory) {
        (, string memory name, string memory version,, address verifyingContract, bytes32 salt,) =
            Kernel(payable(account)).eip712Domain();
        return abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), verifyingContract, salt);
    }

    /// @dev TypedDataSign type hash without chainId for replayable mode
    function _typedDataSignTypeHashReplayable(bytes memory contentsType, bytes memory contentsName)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
    }
}
