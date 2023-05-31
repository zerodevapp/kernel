pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/ECDSAKernelFactory.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        bytes memory bytecode = type(KernelFactory).creationCode;
        bool success;
        bytes memory returnData;
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode, abi.encode(IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789))));
        require(success, "Failed to deploy KernelFactory");
        console.logBytes(returnData);
        address kernelFactory = address(bytes20(returnData));
        console.log("KernelFactory deployed at: %s", kernelFactory);

        bytecode = type(ECDSAValidator).creationCode;
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode));
        require(success, "Failed to deploy ECDSAValidator");
        address validator = address(bytes20(returnData));
        console.log("ECDSAValidator deployed at: %s", validator);

        bytecode = type(ECDSAKernelFactory).creationCode;
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode, abi.encode(kernelFactory), abi.encode(validator), abi.encode(IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789))));
        require(success, "Failed to deploy ECDSAKernelFactory");
        address ecdsaFactory = address(bytes20(returnData));
        console.log("ECDSAKernelFactory deployed at: %s", ecdsaFactory);
        vm.stopBroadcast();
    }
}

