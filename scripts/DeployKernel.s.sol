pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "account-abstraction/interfaces/IStakeManager.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address payable constant EXPECTED_KERNEL_ADDRESS = payable(0xA87e80ed52992e4FB0809fc0B1c0629CF6d43F17);
    address payable constant EXPECTED_KERNEL_FACTORY_ADDRESS = payable(0xeBf88f6f78b3aBD60744699c06e97415d2fE15Bb);
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        Kernel kernel = new Kernel(IEntryPoint(ENTRYPOINT_0_6));
        bytes memory code = address(kernel).code;
        vm.startBroadcast(key);
        KernelFactory factory;
        if(EXPECTED_KERNEL_FACTORY_ADDRESS.code.length == 0){
          factory = new KernelFactory{salt:0}(DEPLOYER);
          console.log("KernelFactory address: %s", address(factory));
        } else {
            factory = KernelFactory(EXPECTED_KERNEL_FACTORY_ADDRESS);
        }
        address expected_addr = factory.getImplementationAddress(keccak256("v2.1"));
        if(expected_addr.code.length == 0 ) {
            kernel = Kernel(payable(factory.deployImplementation(keccak256("v2.1"), code)));
            console.log("Kernel address: %s", address(kernel));
        } else {
            console.log("already deployed on %s", expected_addr);
        }
        vm.stopBroadcast();
    }
}

