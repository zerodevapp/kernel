pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant EXPECTED_VALIDATOR_ADDRESS = 0xd9AB5096a832b9ce79914329DAEE236f8Eea0390;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        if(EXPECTED_VALIDATOR_ADDRESS.code.length == 0) {
            ECDSAValidator validator = new ECDSAValidator{salt:0}();
            console.log("validator address: %s", address(validator));
        } else {
            console.log("validator address: %s", EXPECTED_VALIDATOR_ADDRESS);
        }
        vm.stopBroadcast();
    }
}

