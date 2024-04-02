
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "src/Kernel.sol";
import "forge-std/console.sol";

contract DeployDeterministic is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_7_ADDR = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        vm.startBroadcast(DEPLOYER);
        Kernel kernel = new Kernel{salt:0}(IEntryPoint(payable(ENTRYPOINT_0_7_ADDR)));
        console.log("Kernel :", address(kernel));
        vm.stopBroadcast();
    }
}

