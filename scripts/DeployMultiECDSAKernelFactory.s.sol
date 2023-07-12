pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/MultiECDSAValidator.sol";
import "src/factory/MultiECDSAKernelFactory.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployMultiECDSAKernelFactory is Script {
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        bytes memory bytecode;
        bool success;
        bytes memory returnData;

        bytecode = type(MultiECDSAValidator).creationCode; 
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode));
        require(success, "Failed to deploy MultiECDSAValidator");
        address validator = address(bytes20(returnData));
        console.log("MultiECDSAValidator deployed at: %s", validator);

        bytecode = type(MultiECDSAKernelFactory).creationCode;
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode, abi.encode(KernelFactory(0x5D006d3880645ec6e254E18C1F879DAC9Dd71A39)), abi.encode(validator), abi.encode(IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789))));
        require(success, "Failed to deploy MultiECDSAKernelFactory");
        address multiEcdsaFactory = address(bytes20(returnData));
        console.log("MultiECDSAKernelFactory deployed at: %s", multiEcdsaFactory);
        vm.stopBroadcast();
    }
}

