pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "account-abstraction/interfaces/IStakeManager.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address constant DEPLOYER = 0x9fD431b7703f94289Ba02034631dcC302717805B;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address payable constant EXPECTED_KERNEL_ADDRESS = payable(0x29C69905F09908C70da2D67a2B3d52B22E71F241); //0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb
    address payable constant EXPECTED_KERNEL_FACTORY_ADDRESS = payable(0xc9683DFF173B60aCeF306525645AE6381726cC45);
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        Kernel kernel;
        if(EXPECTED_KERNEL_ADDRESS.code.length == 0 ){
            kernel = new Kernel{salt:0}(IEntryPoint(ENTRYPOINT_0_6));
            console.log("Kernel address: %s", address(kernel));
        } else {
            kernel = Kernel(EXPECTED_KERNEL_ADDRESS);
        }
        KernelFactory factory;
        if(EXPECTED_KERNEL_FACTORY_ADDRESS.code.length == 0){
            factory = new KernelFactory{salt:0}(DEPLOYER, IEntryPoint(ENTRYPOINT_0_6));
            console.log("KernelFactory address: %s", address(factory));
        } else {
            factory = KernelFactory(EXPECTED_KERNEL_FACTORY_ADDRESS);
        }
        if(factory.isAllowedImplementation(address(kernel)) == false) {
            console.log("Registering kernel implementation");
            factory.setImplementation(address(kernel), true);
        }
        // IEntryPoint entryPoint = IEntryPoint(ENTRYPOINT_0_6);
        // IStakeManager.DepositInfo memory info = entryPoint.getDepositInfo(address(factory));
        // if(info.stake == 0) {
        //     console.log("Need to stake to factory");
        // }
        vm.stopBroadcast();
    }
}

