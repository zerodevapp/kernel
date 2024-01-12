pragma solidity ^0.8.0;

import "src/validator/WeightedECDSAValidator.sol";
import "src/executor/RecoveryAction.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployWeightedECDSA is Script {
    address constant EXPECTED_ADDRESS_WEIGHTED_ECDSA_VALIDATOR = 0x4fd47D861c349bD49DC61341a922cb72F9dF7E8d;
    address constant EXPECTED_ADDRESS_RECOVERY_ACTION = 0x2f65dB8039fe5CAEE0a8680D2879deB800F31Ae1;

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        if (EXPECTED_ADDRESS_WEIGHTED_ECDSA_VALIDATOR.code.length == 0) {
            console.log("deploying WeightedECDSAValidator");
            WeightedECDSAValidator validator = new WeightedECDSAValidator{salt:0}();
            console.log("validator address: %s", address(validator));
        } else {
            console.log("validator address: %s", address(EXPECTED_ADDRESS_WEIGHTED_ECDSA_VALIDATOR));
        }
        if (EXPECTED_ADDRESS_RECOVERY_ACTION.code.length == 0) {
            console.log("deploying RecoveryAction");
            RecoveryAction action = new RecoveryAction{salt:0}();
            console.log("RecoveryAction address: %s", address(action));
        } else {
            console.log("RecoveryAction address: %s", address(EXPECTED_ADDRESS_RECOVERY_ACTION));
        }
        vm.stopBroadcast();
    }
}
