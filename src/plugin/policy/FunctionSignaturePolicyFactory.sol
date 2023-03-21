// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./FunctionSignaturePolicy.sol";

contract FunctionSignaturePolicyFactory {
    event NewPolicy(address indexed policy);

    function deploy(Policy[] memory _policies) external returns(FunctionSignaturePolicy) {
        FunctionSignaturePolicy policy = new FunctionSignaturePolicy{salt:keccak256(abi.encodePacked("ZeroDev"))}(_policies);
        emit NewPolicy(address(policy));
        return policy;
    }

    function getPolicy(Policy[] memory _policies) public view returns(FunctionSignaturePolicy) {
        bytes memory initCode = abi.encodePacked(
            type(FunctionSignaturePolicy).creationCode,
            abi.encode(_policies)
        );
        bytes32 salt = keccak256(abi.encodePacked("ZeroDev"));
        
        return FunctionSignaturePolicy(Create2.computeAddress(salt, keccak256(initCode), address(this)));
    }
}
