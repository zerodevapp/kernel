pragma solidity ^0.8.0;

import "src/paymaster/VerifyingPaymaster.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployVerifyingPaymaster is Script {
    address constant DEPLOYER = 0x9fD431b7703f94289Ba02034631dcC302717805B;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    // address constant EXPECTED_VALIDATOR_ADDRESS = 0x93513fB6ea522d47ed8595f1B5037bd88578A914;  //0x02c79162232843C3a1AAe42143087a848a525292;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        address verifyingSigner = 0xBa9CFe6A44979ADdDbF9F4342c65c4Da9C5b207B;
        VerifyingPaymaster paymaster = new VerifyingPaymaster{salt:"0x31"}(IEntryPoint(ENTRYPOINT_0_6), verifyingSigner);
        console.log("paymaster address: %s", address(paymaster));
        vm.stopBroadcast();
    }
}

