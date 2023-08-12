pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/SocialRecoveryValidator.sol";
import "src/factory/RecoveryKernelFactory.sol";
import "src/validator/ERC165SessionKeyValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeploySocialRecovery is Script {
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        SocialRecoveryValidator action = new SocialRecoveryValidator();
        bool success;
        bytes memory returnData;

        bytes memory bytecode1 = type(SocialRecoveryValidator).creationCode; 
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode1, abi.encode(action)));
        require(success, "Failed to deploy SocialRecoveryValidator");
        address validator = address(bytes20(returnData));
        console.log("SocialRecoveryValidator deployed at: %s", validator);

        bytes memory bytecode2 = type(RecoveryKernelFactory).creationCode;
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode2, abi.encode(KernelFactory(0x7A0D94F55792C434d74a40883C6ed8545E406D12)), abi.encode(address(validator)), abi.encode(IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789))));
        require(success, "Failed to deploy RecoveryKernelFactory");
        address recoveryFactory = address(bytes20(returnData));
        console.log("RecoveryKernelFactory deployed at: %s", recoveryFactory);
        vm.stopBroadcast();
    }
}