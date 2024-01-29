pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/utils/P256VerifierWrapper.sol";
import "src/validator/webauthn//WebAuthnFclValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployWebAuthnFclValidator is Script {
    
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        P256VerifierWrapper p256VerifierWrapper = new P256VerifierWrapper{salt:0}();
        console.log("p256 wrapper address: %s", address(p256VerifierWrapper));
        
        WebAuthnFclValidator validator = new WebAuthnFclValidator{salt:0}(address(p256VerifierWrapper));
        console.log("validator address: %s", address(validator));
            
        vm.stopBroadcast();
    }
}

