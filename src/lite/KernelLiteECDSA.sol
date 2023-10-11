pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {Kernel} from  "../Kernel.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED, KERNEL_STORAGE_SLOT_1} from "../common/Constants.sol";
import {ExecutionDetail} from "../common/Structs.sol";
import {packValidationData} from "../common/Types.sol";
import {_intersectValidationData} from "../utils/KernelHelper.sol";

struct KernelLiteECDSAStorage {
    address owner;
}

contract KernelLiteECDSA is Kernel, IKernelValidator {
    error InvalidAccess();
    address public immutable THIS_ADDRESS;
    bytes32 private constant KERNEL_LITE_ECDSA_STORAGE_SLOT =
        0xdea7fea882fba743201b2aeb1babf326b8944488db560784858525d123ee7e97; // keccak256(abi.encodePacked("zerodev.kernel.lite.ecdsa")) - 1

    // for enabling kernelLiteECDSA to be used as validator on upgrade scenario
    // NOTE: should not be accessed if kernel is not being used as validator
    mapping(address => KernelLiteECDSAStorage) public kernelLiteECDSAStorage;

    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {
        THIS_ADDRESS = address(this);
        getKernelLiteECDSAStorage().owner = address(1); // set owner to non-zero address to prevent initialization
    }

    // FOR VALIDATOR USAGE
    function enable(bytes calldata _data) external payable override {
        if(address(this) != THIS_ADDRESS) {
            revert InvalidAccess();
        }
        address owner = address(bytes20(_data[0:20]));
        kernelLiteECDSAStorage[msg.sender].owner = owner;
    }

    function disable(bytes calldata _data) external payable override {
        if(address(this) != THIS_ADDRESS) {
            revert InvalidAccess();
        }
        delete kernelLiteECDSAStorage[msg.sender];
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 userOpHash, uint256 missingAccountFunds) external payable override(IKernelValidator, Kernel) returns(ValidationData validationData) {
        if(address(this) != THIS_ADDRESS) {
            if (msg.sender != address(entryPoint)) {
                revert NotEntryPoint();
            }
            bytes calldata userOpSignature;
            uint256 userOpEndOffset;
            assembly {
                userOpEndOffset := add(calldataload(0x04), 0x24)
                userOpSignature.offset := add(calldataload(add(userOpEndOffset, 0x120)), userOpEndOffset)
                userOpSignature.length := calldataload(sub(userOpSignature.offset, 0x20))
            }
            // mode based signature
            bytes4 mode = bytes4(userOpSignature[0:4]); // mode == 00..00 use validators
            // mode == 0x00000000 use sudo validator
            if (mode == 0x00000000) {
                // sudo mode (use default validator)
                if (missingAccountFunds != 0) {
                    assembly {
                        pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                    }
                    //ignore failure (its EntryPoint's job to verify, not account.)
                }
                // short circuit here for default validator
                return _validateUserOp(_userOp, userOpHash, missingAccountFunds);
            }

            UserOperation memory userOp = _userOp;

            // mode == 0x00000001 use given validator
            // mode == 0x00000002 enable validator
            IKernelValidator validator;
            bytes32 storage_slot_1;
            assembly {
                storage_slot_1 := sload(KERNEL_STORAGE_SLOT_1)
            }
            if (mode & (storage_slot_1 << 224) != 0x00000000) {
                revert DisabledMode();
            } else if (mode == 0x00000001) {
                bytes calldata userOpCallData;
                assembly {
                    userOpCallData.offset := add(calldataload(add(userOpEndOffset, 0x40)), userOpEndOffset)
                    userOpCallData.length := calldataload(sub(userOpCallData.offset, 0x20))
                }
                ExecutionDetail storage detail = getKernelStorage().execution[bytes4(userOpCallData[0:4])];
                validator = detail.validator;
                userOpSignature = userOpSignature[4:];
                validationData = packValidationData(detail.validAfter, detail.validUntil);
            } else if (mode == 0x00000002) {
                bytes calldata userOpCallData;
                assembly {
                    userOpCallData.offset := add(calldataload(add(userOpEndOffset, 0x40)), userOpEndOffset)
                    userOpCallData.length := calldataload(sub(userOpCallData.offset, 0x20))
                }
                // use given validator
                // userOpSignature[4:10] = validAfter,
                // userOpSignature[10:16] = validUntil,
                // userOpSignature[16:36] = validator address,
                (validator, validationData, userOpSignature) =
                    _approveValidator(bytes4(userOpCallData[0:4]), userOpSignature);
            } else {
                return SIG_VALIDATION_FAILED;
            }
            if (missingAccountFunds != 0) {
                assembly {
                    pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                }
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
            userOp.signature = userOpSignature;
            validationData =
                _intersectValidationData(validationData, validator.validateUserOp(userOp, userOpHash, missingAccountFunds));
            return validationData;
        }
        // this means this is being used as validator
        return _validateUserOp(_userOp, userOpHash, missingAccountFunds);
    }

    function validCaller(address _caller, bytes calldata _data) external view override returns(bool) {
        if(address(this) != THIS_ADDRESS) {
            revert InvalidAccess();
        }
        // this means this is being used as validator
        return _caller == kernelLiteECDSAStorage[msg.sender].owner;
    }

    function validateSignature(bytes32 _hash, bytes calldata _signature) external view override returns(ValidationData) {
        if(address(this) != THIS_ADDRESS) {
            revert InvalidAccess();
        }
        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_hash), _signature);
        if (signed == kernelLiteECDSAStorage[msg.sender].owner) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }

//    function isValidSignature(bytes32 _hash, bytes calldata _signature) external view override returns(bytes4) {
//        if(address(this) != THIS_ADDRESS) {
//            super.isValidSignature(_hash, _signature);
//        }
//        // this means this is being used as validator
//        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_hash), _signature);
//        if (signed == kernelLiteECDSAStorage[msg.sender].owner) {
//            return 0x1626ba7e;
//        }
//        return 0xffffffff;
//    }

    // FOR KERNEL USAGE
    function getKernelLiteECDSAStorage() internal pure returns (KernelLiteECDSAStorage storage s) {
        assembly {
            s.slot := KERNEL_LITE_ECDSA_STORAGE_SLOT
        }
    }

    function _setInitialData(IKernelValidator _validator, bytes calldata _data) internal override {
        require(address(_validator) == THIS_ADDRESS, "KernelLiteECDSA: invalid validator");
        require(getKernelLiteECDSAStorage().owner == address(0), "KernelLiteECDSA: already initialized");
        address owner = address(bytes20(_data[0:20]));
        getKernelLiteECDSAStorage().owner = owner;
    }

    function _validateUserOp(UserOperation calldata _op, bytes32 _opHash, uint256)
        internal
        view
        override
        returns (ValidationData)
    {
        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_opHash), _op.signature[4:]); // note that first 4 bytes are for modes
        if (signed != getKernelLiteECDSAStorage().owner) {
            return SIG_VALIDATION_FAILED;
        }
        return ValidationData.wrap(0);
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        override
        returns (ValidationData)
    {
        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_hash), _signature);
        if (signed == getKernelLiteECDSAStorage().owner) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }

    function _validCaller(address _caller, bytes calldata) internal view override returns (bool) {
        return _caller == getKernelLiteECDSAStorage().owner;
    }

    function setDefaultValidator(IKernelValidator, bytes calldata) external payable override onlyFromEntryPointOrSelf {
        revert("not implemented");
    }
}
