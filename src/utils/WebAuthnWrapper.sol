// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";

/// @title WebAuthnWrapper
/// @author rdubois-crypto
/// @author obatirou
/// @author KONFeature
/// @notice A library used to verify ECDSA signatures over secp256r1 through
///         EIP-1271 of Webauthn payloads.
/// From https://github.com/cometh-game/p256-signer/blob/main/contracts/FCL/WrapperFCLWebAuthn.sol
/// And https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_Webauthn.sol
/// @dev This lib is only a wrapper around the FCL_WebAuthn library.
///      It is meant to be used with 1271 signatures.
///      The wrapping is necessary because the FCL_WebAuthn has only internal
///      functions and use calldata. This makes it impossible to use it with
///      isValidSignature that use memory.
///      It's also needed to prevent all the early exit, and so making it
///      impossible to have a precise gas estimation for the verification phase.
library WebAuthnWrapper {
    /// @dev Check the validity of a signature
    function checkSignature(
        bytes calldata authenticatorData,
        bytes1 authenticatorDataFlagMask,
        bytes calldata clientData,
        bytes32 clientChallenge,
        uint256 clientChallengeDataOffset,
        uint256[2] calldata rs,
        uint256[2] calldata xy
    ) external view returns (bool) {
        // Format the msg signed via the p256 curve
        bytes32 message = formatWebAuthNChallenge(
            authenticatorData, authenticatorDataFlagMask, clientData, clientChallenge, clientChallengeDataOffset, rs
        );

        // Perform the verification
        return FCL_ecdsa_utils.ecdsa_verify(message, rs, xy);
    }

    /// @dev Format a web auth n message, return the challenge that has been signed by the user
    function formatWebAuthNChallenge(
        bytes calldata authenticatorData,
        bytes1 authenticatorDataFlagMask,
        bytes calldata clientData,
        bytes32 clientChallenge,
        uint256 clientChallengeDataOffset,
        uint256[2] calldata // rs
    ) internal pure returns (bytes32) {
        // Let the caller check if User Presence (0x01) or User Verification (0x04) are set
        {
            if ((authenticatorData[32] & authenticatorDataFlagMask) != authenticatorDataFlagMask) {
                // TODO: Cleanup that stuff until we are aable to generate offchain dummy sig that pass that verification
                return 0;
            }
            // Verify that clientData commits to the expected client challenge
            // Use the Base64Url encoding which omits padding characters to match WebAuthn Specification
            string memory challengeEncoded = Base64Url.encode(abi.encodePacked(clientChallenge));
            bytes memory challengeExtracted = new bytes(bytes(challengeEncoded).length);

            assembly {
                calldatacopy(
                    add(challengeExtracted, 32),
                    add(clientData.offset, clientChallengeDataOffset),
                    mload(challengeExtracted)
                )
            }

            bytes32 moreData; //=keccak256(abi.encodePacked(challengeExtracted));
            assembly {
                moreData := keccak256(add(challengeExtracted, 32), mload(challengeExtracted))
            }

            if (keccak256(abi.encodePacked(bytes(challengeEncoded))) != moreData) {
                // TODO: Cleanup that stuff until we are aable to generate offchain dummy sig that pass that verification
                return 0;
            }
        } //avoid stack full

        // Verify the signature over sha256(authenticatorData || sha256(clientData))
        bytes memory verifyData = new bytes(authenticatorData.length + 32);

        assembly {
            calldatacopy(add(verifyData, 32), authenticatorData.offset, authenticatorData.length)
        }

        bytes32 more = sha256(clientData);
        assembly {
            mstore(add(verifyData, add(authenticatorData.length, 32)), more)
        }

        return sha256(verifyData);
    }
}
