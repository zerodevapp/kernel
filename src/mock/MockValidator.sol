pragma solidity ^0.8.0;

import "../interfaces/IERC7579Modules.sol";
import "../utils/ModuleTypeLib.sol";

contract MockValidator is IValidator {
    mapping(address => bool) public initialized;
    bool public success;
    uint256 public count;

    mapping(address => bytes) public validatorData;
    mapping(bytes32 => bool) public validSig;
    function sudoSetSuccess(bool _success) external {
        success = _success;
    }

    function sudoSetValidSig( bytes calldata sig) external {
        validSig[keccak256(sig)] = true;
    }

    function onInstall(bytes calldata data) external {
        initialized[msg.sender] = true;
        validatorData[msg.sender] = data;
    }

    function onUninstall(bytes calldata data) external {
        initialized[msg.sender] = false;
        validatorData[msg.sender] = data;
    }

    function isModuleType(uint256 typeID) external view returns (bool) {
        return typeID == 1;
    }

    function getModuleTypes() external view returns (EncodedModuleTypes) {
        ModuleType[] memory types = new ModuleType[](1);
        types[0] = ModuleType.wrap(1);
        ModuleTypeLib.bitEncode(types);
    }

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return initialized[smartAccount];
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256) {
        count++;

        if (success) {
            return 0;
        } else {
            return 1;
        }
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4)
    {
        if (validSig[keccak256(sig)] == true) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }
}
