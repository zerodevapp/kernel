pragma solidity ^0.8.0;

import "../KernelLite.sol";

struct KernelLiteECDSAStorage {
    address owner;
}

contract KernelLiteECDSA is KernelLite {
    bytes32 constant private KERNEL_LITE_ECDSA_STORAGE_SLOT = 0xdea7fea882fba743201b2aeb1babf326b8944488db560784858525d123ee7e97; // keccak256(abi.encodePacked("zerodev.kernel.lite.ecdsa")) - 1

    constructor(IEntryPoint _entryPoint) KernelLite(_entryPoint) {
        getKernelLiteECDSAStorage().owner = address(1); // set owner to non-zero address to prevent initialization
    }

    function getKernelLiteECDSAStorage() internal pure returns (KernelLiteECDSAStorage storage s) {
        assembly {
            s.slot := KERNEL_LITE_ECDSA_STORAGE_SLOT
        }
    }

    function _setInitialData(IKernelValidator, bytes calldata _data) internal override {
        require(getKernelLiteECDSAStorage().owner == address(0), "KernelLiteECDSA: already initialized");
        address owner = address(bytes20(_data[0:20]));
        getKernelLiteECDSAStorage().owner = owner;
    }
    
    function _validateUserOp(UserOperation calldata _op, bytes32 _opHash, uint256) internal view override returns(ValidationData) {
        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_opHash), _op.signature[4:]); // note that first 4 bytes are for modes
        if (signed != getKernelLiteECDSAStorage().owner) {
            return SIG_VALIDATION_FAILED;
        }
        return ValidationData.wrap(0);
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view override returns(ValidationData) {
        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_hash), _signature);
        if (signed == getKernelLiteECDSAStorage().owner) {
            return ValidationData.wrap(0);
        }
        if( ECDSA.recover(_hash, _signature) == getKernelLiteECDSAStorage().owner) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }

    function _validCaller(address _caller, bytes calldata) internal view override returns (bool) {
        return _caller == getKernelLiteECDSAStorage().owner;
    }
}
