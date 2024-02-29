pragma solidity ^0.8.0;

import "src/validator/KillSwitchValidator.sol";
import "src/executor/KillSwitchAction.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployKillSwitch is Script {
    address constant EXPECTED_ADDRESS_KILL_SWITCH_VALIDATOR = 0x7393A7dA58CCfFb78f52adb09705BE6E20F704BC;
    address constant EXPECTED_ADDRESS_KILL_SWITCH_ACTION = 0x3f38e479304c7F18F988269a1bDa7d646bd48243;

    function run() public {
        uint256 key = vm.envUint("TESTNET_DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        KillSwitchValidator validator;
        if (EXPECTED_ADDRESS_KILL_SWITCH_VALIDATOR.code.length == 0) {
            console.log("deploying KillSwitchValidator");
            validator = new KillSwitchValidator{salt: 0}();
            console.log("validator address: %s", address(validator));
        } else {
            validator = KillSwitchValidator(EXPECTED_ADDRESS_KILL_SWITCH_VALIDATOR);
            console.log("validator address: %s", address(EXPECTED_ADDRESS_KILL_SWITCH_VALIDATOR));
        }
        if (EXPECTED_ADDRESS_KILL_SWITCH_ACTION.code.length == 0) {
            console.log("deploying KillSwitchAction");
            KillSwitchAction action = new KillSwitchAction{salt: 0}(validator);
            console.log("KillSwitchAction address: %s", address(action));
        } else {
            console.log("KillSwitchAction address: %s", address(EXPECTED_ADDRESS_KILL_SWITCH_ACTION));
        }
        vm.stopBroadcast();
    }
}
