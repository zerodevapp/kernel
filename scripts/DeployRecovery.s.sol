pragma solidity ^0.8.0;

import "src/validator/WeightedECDSAValidator.sol";
import "src/executor/RecoveryAction.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployRecovery is Script  {
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        RecoveryAction action = new RecoveryAction();
        console.log("Deploying RecoveryAction at address: ", address(action));
        WeightedECDSAValidator validator = new WeightedECDSAValidator();
        console.log("Deploying WeightedECDSAValidator at address: ", address(validator));
        vm.stopBroadcast();
    }
}
