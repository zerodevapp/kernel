pragma solidity ^0.8.0;

import "src/validator/WeightedECDSAValidator.sol";
import "src/executor/RecoveryAction.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployRecovery is Script {
    function run() public {
        address deployer = vm.envAddress("DEPLOYER");
        vm.startBroadcast(deployer);
        console.log("Deployer address: ", deployer);
        //RecoveryAction action = new RecoveryAction{salt:0}();
        //console.log("Deploying RecoveryAction at address: ", address(action));
        WeightedECDSAValidator validator = new WeightedECDSAValidator{salt: 0}();
        console.log("Deploying WeightedECDSAValidator at address: ", address(validator));
        vm.stopBroadcast();
    }
}
