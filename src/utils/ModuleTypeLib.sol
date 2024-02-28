// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

type EncodedModuleTypes is uint256;

type ModuleType is uint256;

library ModuleTypeLib {
    function isType(EncodedModuleTypes self, ModuleType moduleType) internal pure returns (bool) {
        return (EncodedModuleTypes.unwrap(self) & 2 ** ModuleType.unwrap(moduleType)) != 0;
    }

    function bitEncode(ModuleType[] memory moduleTypes) internal pure returns (EncodedModuleTypes) {
        uint256 result;
        for (uint256 i; i < moduleTypes.length; i++) {
            result = result | uint256(2 ** ModuleType.unwrap(moduleTypes[i]));
        }
        return EncodedModuleTypes.wrap(result);
    }

    function bitEncodeCalldata(ModuleType[] calldata moduleTypes) internal pure returns (EncodedModuleTypes) {
        uint256 result;
        for (uint256 i; i < moduleTypes.length; i++) {
            result = result + uint256(2 ** ModuleType.unwrap(moduleTypes[i]));
        }
        return EncodedModuleTypes.wrap(result);
    }
}
