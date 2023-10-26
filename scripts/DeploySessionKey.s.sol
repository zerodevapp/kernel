pragma solidity ^0.8.0;

import "src/validator/SessionKeyValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeploySessionKey is Script {
    address constant EXPECTED_ADDRESS_SESSION_KEY_VALIDATOR = 0x1C1D5b70aD6e0c04366aab100261A6Bcc251EA3f;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
//        if(EXPECTED_ADDRESS_SESSION_KEY_VALIDATOR.code.length == 0) {
            console.log("deploying SessionKeyValidator");
            SessionKeyValidator validator = new SessionKeyValidator{salt:0}();
            console.log("validator address: %s", address(validator));
 //       }
        vm.stopBroadcast();
    }
}

