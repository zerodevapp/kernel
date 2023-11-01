pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address constant DEPLOYER = 0x9fD431b7703f94289Ba02034631dcC302717805B;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant EXPECTED_VALIDATOR_ADDRESS = 0x93513fB6ea522d47ed8595f1B5037bd88578A914;  //0x02c79162232843C3a1AAe42143087a848a525292;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        ECDSAValidator validator = new ECDSAValidator{salt:"0x31"}();
        console.log("validator address: %s", address(validator));
        // if(EXPECTED_VALIDATOR_ADDRESS.code.length == 0) {
        //     ECDSAValidator validator = new ECDSAValidator{salt:0}();
        //     console.log("validator address: %s", address(validator));
        // } else {
        //     console.log("validator address: %s", EXPECTED_VALIDATOR_ADDRESS);
        // }
        vm.stopBroadcast();
    }
}

