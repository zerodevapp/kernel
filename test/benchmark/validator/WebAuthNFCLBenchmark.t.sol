// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Kernel} from "src/Kernel.sol";
import {ERC4337Utils} from "src/utils/ERC4337Utils.sol";

import {WebAuthnFclValidator} from "src/validator/webauthn/WebAuthnFclValidator.sol";
import {WebAuthnFclVerifier} from "src/validator/webauthn/WebAuthnFclVerifier.sol";
import {P256VerifierWrapper} from "src/utils/P256VerifierWrapper.sol";

import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";

import {BaseValidatorBenchmark} from "../BaseValidatorBenchmark.t.sol";
import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

using ERC4337Utils for IEntryPoint;

/// @dev Benchmark of the WebAuthN FCL validator
/// @author KONFeature
contract WebAuthnFclBenchmark is BaseValidatorBenchmark {
    // Curve order (number of points)
    uint256 constant n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /// @dev The current validator we will benchmark
    WebAuthnFclValidator private _webAuthnFclValidator;

    /// @dev The p256 sig wrapper we will use to validate the sig
    P256VerifierWrapper private _p256Wrapper;

    /// @dev Simple tester contract that will help us with sig manangement
    WebAuthNHelper private _webAuthNHelper;

    /// @dev the owner of the kernel wallet we will test
    uint256 private _ownerX;
    uint256 private _ownerY;
    uint256 private _ownerPrivateKey;

    function setUp() public virtual {
        // Init test suite
        _init();

        // Deploy the webauthn validator
        _p256Wrapper = new P256VerifierWrapper();
        _webAuthnFclValidator = new WebAuthnFclValidator(address(_p256Wrapper));
        _validator = _webAuthnFclValidator;

        // Deploy our helper
        _webAuthNHelper = new WebAuthNHelper();

        // Create the webAuthN owner
        (, _ownerPrivateKey) = makeAddrAndKey("webAuthNOwner");
        (_ownerX, _ownerY) = _getPublicKey(_ownerPrivateKey);

        // Init test suite
        _setupKernel();
    }

    /// @dev Get the current validator anme (used for the json output)
    function _getValidatorName() internal view virtual override returns (string memory) {
        return "FclWebAuthN";
    }

    /// @dev The enabled data are used for mode 2, when the validator isn't enabled and should be enable before
    function _getEnableData() internal view virtual override returns (bytes memory) {
        return abi.encodePacked(_ownerX, _ownerY);
    }

    /// @dev Fetch the data used to disable a kernel account
    function _getDisableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    /// @dev Generate the signature for the given `_userOperation`
    function _generateUserOpSignature(UserOperation memory _userOperation)
        internal
        view
        virtual
        override
        returns (bytes memory)
    {
        bytes32 userOpHash = _entryPoint.getUserOpHash(_userOperation);
        return _generateWebAuthnSignature(_ownerPrivateKey, userOpHash);
    }

    /// @dev Generate the signature for the given `_hash`
    function _generateHashSignature(bytes32 _hash) internal view virtual override returns (bytes memory) {
        return _generateWebAuthnSignature(_ownerPrivateKey, _hash);
    }
    /// @dev Generate the signature for the given `_hash`

    function _generateWrongHashSignature(bytes32 _hash) internal view virtual override returns (bytes memory) {
        // If we modify the hash for webauthn it will early exit, cause bad challenge, so need to modify the owner
        return _generateWebAuthnSignature(_ownerPrivateKey + 1, _hash);
    }

    /* -------------------------------------------------------------------------- */
    /*                             WebAuthN utilities                             */
    /* -------------------------------------------------------------------------- */

    /// @dev Generate a webauthn signature for the given `_hash` using the given `_privateKey`
    function _generateWebAuthnSignature(uint256 _privateKey, bytes32 _hash)
        internal
        view
        returns (bytes memory signature)
    {
        (bytes32 msgToSign, bytes memory authenticatorData, bytes memory clientData, uint256 clientChallengeDataOffset)
        = _prepapreWebAuthnMsg(_hash);

        // Get the signature
        (uint256 r, uint256 s) = _getP256Signature(_privateKey, msgToSign);
        uint256[2] memory rs = [r, s];

        // Return the signature
        return abi.encode(authenticatorData, clientData, clientChallengeDataOffset, rs);
    }

    /// @dev Prepare all the base data needed to perform a webauthn signature o n the given `_hash`
    function _prepapreWebAuthnMsg(bytes32 _hash)
        internal
        view
        returns (
            bytes32 msgToSign,
            bytes memory authenticatorData,
            bytes memory clientData,
            uint256 clientChallengeDataOffset
        )
    {
        // Base Mapping of the message
        bytes memory encodedChallenge = bytes(Base64Url.encode(abi.encodePacked(_hash)));

        // Prepare the authenticator data (from a real webauthn challenge)
        authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        // Prepare the client data (starting from a real webauthn challenge, then replacing only the bytes needed for the challenge)
        bytes memory clientDataStart = hex"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22";
        bytes memory clientDataEnd =
            hex"222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303032222c2263726f73734f726967696e223a66616c73657d";
        clientData = bytes.concat(clientDataStart, encodedChallenge, clientDataEnd);
        clientChallengeDataOffset = 36;

        // Build the signature layout
        WebAuthnFclVerifier.FclSignatureLayout memory sigLayout = WebAuthnFclVerifier.FclSignatureLayout({
            authenticatorData: authenticatorData,
            clientData: clientData,
            challengeOffset: clientChallengeDataOffset,
            // R/S not needed since the formatter will only use the other data
            rs: [uint256(0), uint256(0)]
        });

        // Format it
        msgToSign = _webAuthNHelper.formatSigLayout(_hash, sigLayout);
    }

    /// @dev Get a public key for a p256 user, from the given `_privateKey`
    function _getPublicKey(uint256 _privateKey) internal view returns (uint256, uint256) {
        return FCL_ecdsa_utils.ecdsa_derivKpub(_privateKey);
    }

    /// @dev Generate a p256 signature, from the given `_privateKey` on the given `_hash`
    function _getP256Signature(uint256 _privateKey, bytes32 _hash) internal pure returns (uint256, uint256) {
        // Generate the signature using the k value and the private key
        (bytes32 r, bytes32 s) = vm.signP256(_privateKey, _hash);
        return (uint256(r), uint256(s));
    }
}

/// @dev simple contract to format a webauthn challenge (using to convert stuff in memory during test to calldata)
contract WebAuthNHelper {
    function formatSigLayout(bytes32 _hash, WebAuthnFclVerifier.FclSignatureLayout calldata signatureLayout)
        public
        view
        returns (bytes32)
    {
        return WebAuthnFclVerifier._formatWebAuthNChallenge(_hash, signatureLayout);
    }
}
