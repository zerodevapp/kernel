pragma solidity ^0.8.0;

import "src/validator/SessionKeyValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeploySessionKey is Script {
    address constant EXPECTED_ADDRESS_SESSION_KEY_VALIDATOR = 0x8e632447954036ee940eB0a6bC5a20A18543C4Fd;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        if(EXPECTED_ADDRESS_SESSION_KEY_VALIDATOR.code.length == 0) {
            console.log("deploying SessionKeyValidator");
            ExecuteSessionKeyValidator validator = new ExecuteSessionKeyValidator{salt:0}();
            console.log("validator address: %s", address(validator));
        } else {
            console.log("validator address: %s", EXPECTED_ADDRESS_SESSION_KEY_VALIDATOR);
        }
        vm.stopBroadcast();
    }
}

