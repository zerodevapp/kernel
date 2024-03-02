import {IValidator, IHook, MODULE_TYPE_VALIDATOR, MODULE_TYPE_HOOK} from "../interfaces/IERC7579Modules.sol";
import {ModuleTypeLib, EncodedModuleTypes, ModuleType} from "../utils/ModuleTypeLib.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";

contract ECDSAValidator is IValidator, IHook {
    mapping(address => address) public owner;

    function onInstall(bytes calldata data) external override {
        owner[msg.sender] = address(bytes20(data[0:20]));
    }

    function onUninstall(bytes calldata data) external override {}

    function isModuleType(uint256 typeID) external view override returns (bool) {
        if (typeID == MODULE_TYPE_VALIDATOR) {
            return true;
        } else if (typeID == MODULE_TYPE_HOOK) {
            return true;
        } else {
            return false;
        }
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return owner[smartAccount] != address(0);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        bytes calldata sig = userOp.signature;
        address signer = ecrecover(userOpHash, uint8(sig[0]), bytes32(sig[1:33]), bytes32(sig[33:65]));
        if (signer == owner[msg.sender]) {
            return 0;
        } else {
            return 1;
        }
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address signer = ecrecover(hash, uint8(sig[0]), bytes32(sig[1:33]), bytes32(sig[33:65]));
        if (signer == owner[sender]) {
            return 0x00000000;
        } else {
            return 0x00000001;
        }
    }

    function preCheck(address msgSender, bytes calldata) external view override returns (bytes memory hookData) {
        require(msgSender == owner[msg.sender], "ECDSAValidator: sender is not owner");
    }

    function postCheck(bytes calldata hookData) external override returns (bool success) {}
}
