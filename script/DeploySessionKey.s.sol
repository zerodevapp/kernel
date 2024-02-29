pragma solidity ^0.8.0;

import "src/validator/SessionKeyValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeploySessionKey is Script {
    address constant EXPECTED_ADDRESS = 0x5C06CE2b673fD5E6e56076e40DD46aB67f5a72A5;

    function run() public {
        address deployer = vm.envAddress("DEPLOYER");
        vm.startBroadcast(deployer);
        console.log("deploying SessionKeyValidator");
        SessionKeyValidator validator = new SessionKeyValidator{salt: 0}();
        console.log("validator address: %s", address(validator));
        vm.stopBroadcast();
    }
}
