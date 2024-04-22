pragma solidity ^0.8.0;

import "src/utils/P256VerifierWrapper.sol";
import "src/validator/webauthn//WebAuthnFclValidator.sol";
import "./DeterministicDeploy.s.sol";
import "forge-std/console.sol";

/// @dev Deterministic deployment of FclWebAuthNValidator
library FclWebAuthnValidatorDeploy {
    address constant EXPECTED_P256_VERIFIER_VALIDATOR_ADDRESS = 0x738e3257EE928637fE62c37F91D3e722C45Dcc7C;

    address constant EXPECTED_WEBAUTHN_VALIDATOR_ADDRESS = 0x42085b533b27B9AfDAF3864a38c72eF853943DAB;

    bytes32 constant DEPLOYMENT_SALT = keccak256("WebAuthNValidator by Frak");

    /// @dev Deploy the P256VerifierWrapper and WebAuthnFclValidator
    function deployWebAuthnFclVerifier() internal {
        // Check if the contract of the p256 verifier is already deployed
        if (EXPECTED_P256_VERIFIER_VALIDATOR_ADDRESS.code.length == 0) {
            _deployOnChainP256();
        } else {
            console.log("P256VerifierWrapper: already deployed");
        }

        // Deploy the WebAuthnFclValidator
        if (EXPECTED_WEBAUTHN_VALIDATOR_ADDRESS.code.length == 0) {
            _deployValidator();
        } else {
            console.log("WebAuthnFclValidator: already deployed");
        }
    }

    /// @dev Deploy the P256VerifierWrapper contract
    function _deployOnChainP256() private {
        P256VerifierWrapper p256Wrapper = new P256VerifierWrapper{salt: DEPLOYMENT_SALT}();
        require(
            address(p256Wrapper) == EXPECTED_P256_VERIFIER_VALIDATOR_ADDRESS,
            "FclWebAuthnValidatorDeploy: p256 wrapper address mismatch"
        );
    }

    /// @dev Deploy the P256VerifierWrapper contract
    function _deployValidator() private {
        WebAuthnFclValidator validator =
            new WebAuthnFclValidator{salt: DEPLOYMENT_SALT}(EXPECTED_P256_VERIFIER_VALIDATOR_ADDRESS);
        require(
            address(validator) == EXPECTED_WEBAUTHN_VALIDATOR_ADDRESS,
            "FclWebAuthnValidatorDeploy: validator address mismatch"
        );
    }
}
