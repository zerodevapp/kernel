pragma solidity ^0.8.0;

import "src/validator/modularPermission/ModularPermissionValidator.sol";
import "src/validator/modularPermission/signers/ECDSASigner.sol";
import "src/validator/modularPermission/policies/GasPolicy.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployModularPermission is Script {
    address constant EXPECTED_MODULAR_PERMISSION_ADDRESS = 0x965Bea0f8b65aABD1F5148F64654BbAAfB9d2Efa;
    address constant EXPECTED_ECDSA_SIGNER_ADDRESS = 0xF9E712F44A360ED8820aD624e41164f74a5a7456;
    address constant EXPECTED_GAS_POLICY_ADDRESS = 0x62868E950Efbb336DCFf033598Ee5E602f0a93cD;

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

        vm.stopBroadcast();
    }
}
