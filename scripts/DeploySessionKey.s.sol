pragma solidity ^0.8.0;

import "src/plugin/ZeroDevSessionKeyPlugin.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeploySessionKey is Script {
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        bytes memory creationBytecode = type(ZeroDevSessionKeyPlugin).creationCode;
        bytes memory returnData;
        bool success;
        (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(creationBytecode);
        require(success, "Failed to deploy");
        vm.stopBroadcast();
        console.log("deployed at : ", address (uint160 (bytes20 (returnData) )) );
    }
}

