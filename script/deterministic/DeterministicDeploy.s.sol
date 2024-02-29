pragma solidity ^0.8.0;

import "forge-std/console.sol";

library DeterministicDeploy {
    address constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function checkDeploy(string memory tag, address _expectedAddress, bytes memory _code) internal {
        if (_expectedAddress.code.length == 0) {
            (bool success, bytes memory addr) = DETERMINISTIC_DEPLOYER.call(_code);
            require(success, "DeterministicDeploy: failed to deploy");
            require(address(bytes20(addr)) == _expectedAddress, "DeterministicDeploy: address mismatch");
            console.log(string.concat(tag, ": deployed at %s"), _expectedAddress);
        } else {
            console.log(string.concat(tag, ": already deployed"));
        }
    }
}
