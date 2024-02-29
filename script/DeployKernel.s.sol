pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "I4337/interfaces/IStakeManager.sol";
import "src/Kernel.sol";
import "src/lite/KernelLiteECDSA.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "src/validator/ECDSAValidator.sol";

contract DeployKernel is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant ECDSAVALIDATOR = 0xd9AB5096a832b9ce79914329DAEE236f8Eea0390;
    address constant EXPECTED_KERNEL_ADDRESS = 0x0DA6a956B9488eD4dd761E59f52FDc6c8068E6B5;
    address constant EXPECTED_KERNEL_LITE_ADDRESS = 0xbEdb61Be086F3f15eE911Cc9AB3EEa945DEbFa96;
    address payable constant EXPECTED_KERNEL_FACTORY_ADDRESS = payable(0x5de4839a76cf55d0c90e2061ef4386d962E15ae3);

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        KernelFactory factory;
        if (EXPECTED_KERNEL_FACTORY_ADDRESS.code.length == 0) {
            factory = new KernelFactory{salt: 0}(DEPLOYER, IEntryPoint(ENTRYPOINT_0_6));
            console.log("KernelFactory address: %s", address(factory));
        } else {
            factory = KernelFactory(EXPECTED_KERNEL_FACTORY_ADDRESS);
        }
        if (EXPECTED_KERNEL_LITE_ADDRESS.code.length == 0) {
            if (address(ECDSAVALIDATOR).code.length == 0) {
                console.log("ECDSAVALIDATOR NOT DEPLOYED");
            } else {
                KernelLiteECDSA kernellite;
                kernellite = new KernelLiteECDSA{salt: 0}(IEntryPoint(ENTRYPOINT_0_6), IKernelValidator(ECDSAVALIDATOR));
                console.log("Kernel Lite address: %s", address(kernellite));
            }
        }
        if (factory.isAllowedImplementation(EXPECTED_KERNEL_LITE_ADDRESS) == false) {
            console.log("Registering kernellite implementation");
            factory.setImplementation(EXPECTED_KERNEL_LITE_ADDRESS, true);
        }
        if (EXPECTED_KERNEL_ADDRESS.code.length == 0) {
            Kernel kernel;
            kernel = new Kernel{salt: 0}(IEntryPoint(ENTRYPOINT_0_6));
            console.log("Kernel address: %s", address(kernel));
        }
        if (factory.isAllowedImplementation(EXPECTED_KERNEL_ADDRESS) == false) {
            console.log("Registering kernel implementation");
            factory.setImplementation(EXPECTED_KERNEL_ADDRESS, true);
        }
        IEntryPoint entryPoint = IEntryPoint(ENTRYPOINT_0_6);
        IStakeManager.DepositInfo memory info = entryPoint.getDepositInfo(address(factory));
        if (info.stake == 0) {
            console.log("Need to stake to factory");
        }
        vm.stopBroadcast();
    }
}
