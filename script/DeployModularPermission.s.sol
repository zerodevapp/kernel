pragma solidity ^0.8.0;

import "src/validator/modularPermission/ModularPermissionValidator.sol";
import "src/validator/modularPermission/signers/ECDSASigner.sol";
import "src/validator/modularPermission/policies/GasPolicy.sol";
import "src/validator/modularPermission/policies/SignaturePolicy.sol";
import "src/validator/modularPermission/policies/SudoPolicy.sol";
import {MerklePolicy} from "src/validator/modularPermission/policies/MerklePolicy.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployModularPermission is Script {
    address constant EXPECTED_MODULAR_PERMISSION_ADDRESS = 0x965Bea0f8b65aABD1F5148F64654BbAAfB9d2Efa;
    address constant EXPECTED_ECDSA_SIGNER_ADDRESS = 0xF9E712F44A360ED8820aD624e41164f74a5a7456;
    address constant EXPECTED_GAS_POLICY_ADDRESS = 0x62868E950Efbb336DCFf033598Ee5E602f0a93cD;
    address constant EXPECTED_MERKLE_POLICY_ADDRESS = 0xb808D75B5ACf6B5513eb816d3980C733ae6Be468;
    address constant EXPECTED_SIGNATURE_POLICY_ADDRESS = 0x60e9a007782EB649B291608dCa9E74Aaa966D122;
    address constant EXPECTED_SUDO_POLICY_ADDRESS = 0x9262C3A894328f9036Aa7a3f0f2cE8CF684ad20f;

    function run() public {
        uint256 key = vm.envUint("TESTNET_DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        if (EXPECTED_MODULAR_PERMISSION_ADDRESS.code.length == 0) {
            console.log("deploying ModularPermissionValidator");
            ModularPermissionValidator validator = new ModularPermissionValidator{salt: 0}();
            console.log("validator address: %s", address(validator));
        } else {
            console.log("validator address: %s", address(EXPECTED_MODULAR_PERMISSION_ADDRESS));
        }

        if (EXPECTED_ECDSA_SIGNER_ADDRESS.code.length == 0) {
            console.log("deploying ECDSASigner");
            ECDSASigner ecdsaSigner = new ECDSASigner{salt: 0}();
            console.log("ecdsaSigner address: %s", address(ecdsaSigner));
        } else {
            console.log("ecdsaSigner address: %s", address(EXPECTED_ECDSA_SIGNER_ADDRESS));
        }

        if (EXPECTED_GAS_POLICY_ADDRESS.code.length == 0) {
            console.log("deploying GasPolicy");
            GasPolicy gasPolicy = new GasPolicy{salt: 0}();
            console.log("gasPolicy address: %s", address(gasPolicy));
        } else {
            console.log("gasPolicy address: %s", address(EXPECTED_GAS_POLICY_ADDRESS));
        }

        if (EXPECTED_MERKLE_POLICY_ADDRESS.code.length == 0) {
            console.log("deploying MerklePolicy");
            MerklePolicy merklePolicy = new MerklePolicy{salt: 0}();
            console.log("merklePolicy address: %s", address(merklePolicy));
        } else {
            console.log("merklePolicy address: %s", address(EXPECTED_MERKLE_POLICY_ADDRESS));
        }

        if (EXPECTED_SIGNATURE_POLICY_ADDRESS.code.length == 0) {
            console.log("deploying SignaturePolicy");
            SignaturePolicy signturePolicy = new SignaturePolicy{salt: 0}();
            console.log("signturePolicy address: %s", address(signturePolicy));
        } else {
            console.log("signturePolicy address: %s", address(EXPECTED_SIGNATURE_POLICY_ADDRESS));
        }

        if (EXPECTED_SUDO_POLICY_ADDRESS.code.length == 0) {
            console.log("deploying SudoPolicy");
            SudoPolicy sudoPolicy = new SudoPolicy{salt: 0}();
            console.log("sudoPolicy address: %s", address(sudoPolicy));
        } else {
            console.log("sudoPolicy address: %s", address(EXPECTED_SUDO_POLICY_ADDRESS));
        }

        vm.stopBroadcast();
    }
}
