pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "src/validator/ECDSAValidator.sol";

contract DeployValidators is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;

    function run() external {
        vm.startBroadcast(DEPLOYER);
        ECDSAValidator validator = new ECDSAValidator{salt: 0}();
        console.log("ECDSA :", address(validator));
        vm.stopBroadcast();
    }
}
