pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "src/validator/ECDSAValidator.sol";


contract CreateAccount is Script {
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        KernelFactory kernelFactory = KernelFactory(0xc9683DFF173B60aCeF306525645AE6381726cC45);
        IKernelValidator defaultValidator = new ECDSAValidator();
        address accountProxy = kernelFactory.createAccount(
            0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb, 
            abi.encodeWithSelector(KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(0x9fD431b7703f94289Ba02034631dcC302717805B)),
            0
        );
        console.log("smart account created at: %s", proxy);
        vm.stopBroadcast();
    }
}

