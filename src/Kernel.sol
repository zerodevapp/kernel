// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Importing external libraries and contracts
import {EIP712} from "solady/utils/EIP712.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {Compatibility} from "./abstract/Compatibility.sol";
import {KernelStorage} from "./abstract/KernelStorage.sol";
import {_intersectValidationData} from "./utils/KernelHelper.sol";
import {IKernelValidator} from "./interfaces/IKernelValidator.sol";

import {
    KERNEL_NAME,
    KERNEL_VERSION,
    VALIDATOR_APPROVED_STRUCT_HASH,
    KERNEL_STORAGE_SLOT_1,
    SIG_VALIDATION_FAILED
} from "./common/Constants.sol";
import {Operation} from "./common/Enums.sol";
import {WalletKernelStorage, Call, ExecutionDetail} from "./common/Structs.sol";
import {ValidationData, ValidAfter, ValidUntil, parseValidationData, packValidationData} from "./common/Types.sol";

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for extensible wallet functionality
contract Kernel is EIP712, Compatibility, KernelStorage {
    /// @dev Selector of the `DisabledMode()` error, to be used in assembly, 'bytes4(keccak256(bytes("DisabledMode()")))', same as DisabledMode.selector()
    uint256 private constant _DISABLED_MODE_SELECTOR = 0xfc2f51c5;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev Current kernel name and version
    string public constant name = KERNEL_NAME;
    string public constant version = KERNEL_VERSION;

    /// @dev Sets up the EIP712 and KernelStorage with the provided entry point
    constructor(IEntryPoint _entryPoint) KernelStorage(_entryPoint) {}

    /// @notice Accepts incoming Ether transactions and calls from the EntryPoint contract
    /// @dev This function will delegate any call to the appropriate executor based on the function signature.
    fallback() external payable {
        bytes4 sig = msg.sig;
        address executor = getKernelStorage().execution[sig].executor;
        if (msg.sender != address(entryPoint) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), executor, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Executes a function call to an external contract
    /// @param to The address of the target contract
    /// @param value The amount of Ether to send
    /// @param data The call data to be sent
    /// @dev operation is deprecated param, use executeBatch for batched transaction
    function execute(address to, uint256 value, bytes memory data, Operation _operation) external payable {
        if (msg.sender != address(entryPoint) && msg.sender != address(this) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        if (_operation != Operation.Call) {
            revert DeprecatedOperation();
        }
        assembly {
            let success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Executes a function call to an external contract with delegatecall
    /// @param to The address of the target contract
    /// @param data The call data to be sent
    function executeDelegateCall(address to, bytes memory data) external payable {
        if (msg.sender != address(entryPoint) && msg.sender != address(this) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        assembly {
            let success := delegatecall(gas(), to, add(data, 0x20), mload(data), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Executes a function call to an external contract batched
    /// @param calls The calls to be executed, in order
    /// @dev operation deprecated param, use executeBatch for batched transaction
    function executeBatch(Call[] memory calls) external payable {
        if (msg.sender != address(entryPoint) && !_checkCaller()) {
            revert NotAuthorizedCaller();
        }
        uint256 len = calls.length;
        for (uint256 i = 0; i < len;) {
            Call memory call = calls[i];
            address to = call.to;
            uint256 value = call.value;
            bytes memory data = call.data;
            assembly {
                let success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
                switch success
                case 0 {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
                default { i := add(i, 1) }
            }
        }
    }

    /// @notice Validates a user operation based on its mode
    /// @dev This function will validate user operation and be called by EntryPoint
    /// @param _userOp The user operation to be validated
    /// @param userOpHash The hash of the user operation
    /// @param missingAccountFunds The funds needed to be reimbursed
    /// @return validationData The data used for validation
    function validateUserOp(UserOperation calldata _userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        virtual
        returns (ValidationData validationData)
    {
        if (msg.sender != address(entryPoint)) {
            revert NotEntryPoint();
        }
        bytes calldata userOpSignature;
        uint256 userOpEndOffset;
        assembly {
            // Store the userOpSignature offset
            userOpEndOffset := add(calldataload(0x04), 0x24)
            // Extract the user op signature from the calldata (but keep it in the calldata, just extract offset & length)
            userOpSignature.offset := add(calldataload(add(userOpEndOffset, 0x120)), userOpEndOffset)
            userOpSignature.length := calldataload(sub(userOpSignature.offset, 0x20))
        }
        // mode based signature
        bytes4 mode = bytes4(userOpSignature[0:4]); // mode == 00..00 use validators
        // mode == 0x00000000 use sudo validator
        if (mode == 0x00000000) {
            assembly {
                if missingAccountFunds {
                    pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                    //ignore failure (its EntryPoint's job to verify, not account.)
                }
            }
            // short circuit here for default validator
            return _validateUserOp(_userOp, userOpHash, missingAccountFunds);
        }

        // Check if the kernel is disabled, if that's the case, it's only accepting userOperation with sudo mode
        assembly ("memory-safe") {
            // Extract the disabled mode from the storage slot
            let isKernelDisabled := shl(224, sload(KERNEL_STORAGE_SLOT_1))
            // If we got a non-zero disabled mode, and non zero mode, then revert
            if and(isKernelDisabled, mode) {
                mstore(0x00, _DISABLED_MODE_SELECTOR)
                revert(0x1c, 0x04)
            }
        }

        // The validator that will be used
        IKernelValidator validator;

        // mode == 0x00000001 use given validator
        // mode == 0x00000002 enable validator
        if (mode == 0x00000001) {
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

        assembly {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
        }

        // Replicate the userOp from memory to calldata, to update it's signature (since with mode 1 & 2 the signatre can be updated)
        UserOperation memory userOp = _userOp;
        userOp.signature = userOpSignature;

        // Get the validator data from the designated signer
        validationData =
            _intersectValidationData(validationData, validator.validateUserOp(userOp, userOpHash, missingAccountFunds));
        return validationData;
    }

    /// @dev This function will approve a new validator for the current kernel
    /// @param sig The signature of the userOp asking for a validator approval
    /// @param signature The signature of the userOp asking for a validator approval
    function _approveValidator(bytes4 sig, bytes calldata signature)
        internal
        returns (IKernelValidator validator, ValidationData validationData, bytes calldata validationSig)
    {
        unchecked {
            validator = IKernelValidator(address(bytes20(signature[16:36])));
            uint256 cursor = 88;
            uint256 length = uint256(bytes32(signature[56:88])); // this is enableDataLength
            bytes calldata enableData;
            assembly {
                enableData.offset := add(signature.offset, cursor)
                enableData.length := length
                cursor := add(cursor, length) // 88 + enableDataLength
            }
            length = uint256(bytes32(signature[cursor:cursor + 32])); // this is enableSigLength
            assembly {
                cursor := add(cursor, 32)
            }
            bytes32 enableDigest = _hashTypedData(
                keccak256(
                    abi.encode(
                        VALIDATOR_APPROVED_STRUCT_HASH,
                        bytes4(sig),
                        uint256(bytes32(signature[4:36])),
                        address(bytes20(signature[36:56])),
                        keccak256(enableData)
                    )
                )
            );
            validationData = _intersectValidationData(
                _validateSignature(address(this), enableDigest, enableDigest, signature[cursor:cursor + length]),
                ValidationData.wrap(
                    uint256(bytes32(signature[4:36]))
                        & 0xffffffffffffffffffffffff0000000000000000000000000000000000000000
                )
            );
            assembly {
                cursor := add(cursor, length)
                validationSig.offset := add(signature.offset, cursor)
                validationSig.length := sub(signature.length, cursor)
            }
            getKernelStorage().execution[sig] = ExecutionDetail({
                validAfter: ValidAfter.wrap(uint48(bytes6(signature[4:10]))),
                validUntil: ValidUntil.wrap(uint48(bytes6(signature[10:16]))),
                executor: address(bytes20(signature[36:56])),
                validator: IKernelValidator(address(bytes20(signature[16:36])))
            });
            validator.enable(enableData);
        }
    }

    /// @dev Validates a signature for the given kernel
    /// @param hash The hash of the data that was signed
    /// @param signature The signature to be validated
    function validateSignature(bytes32 hash, bytes calldata signature) public view returns (ValidationData) {
        return _validateSignature(msg.sender, hash, hash, signature);
    }

    /// @dev Get the current name & version of the kernel, used for the EIP-712 domain separator
    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return (name, version);
    }

    /// @dev Get an EIP-712 compliant domain separator
    function _domainSeparator() internal view override returns (bytes32) {
        // Obtain the name and version from the _domainNameAndVersion function.
        (string memory _name, string memory _version) = _domainNameAndVersion();
        bytes32 nameHash = keccak256(bytes(_name));
        bytes32 versionHash = keccak256(bytes(_version));

        // Use the proxy address for the EIP-712 domain separator.
        address proxyAddress = address(this);

        // Construct the domain separator with name, version, chainId, and proxy address.
        bytes32 typeHash = EIP712_DOMAIN_TYPEHASH;
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, proxyAddress));
    }

    /// @notice Checks if a signature is valid
    /// @dev This function checks if a signature is valid based on the hash of the data signed.
    /// @param hash The hash of the data that was signed
    /// @param signature The signature to be validated
    /// @return The magic value 0x1626ba7e if the signature is valid, otherwise returns 0xffffffff.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        // Include the proxy address in the domain separator
        bytes32 domainSeparator = _domainSeparator();

        // Recreate the signed message hash with the correct domain separator
        bytes32 signedMessageHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, hash));

        ValidationData validationData = _validateSignature(msg.sender, signedMessageHash, hash, signature);
        (ValidAfter validAfter, ValidUntil validUntil, address result) = parseValidationData(validationData);

        // Check if the signature is valid within the specified time frame and the result is successful
        if (
            ValidAfter.unwrap(validAfter) <= block.timestamp && ValidUntil.unwrap(validUntil) >= block.timestamp
                && result == address(0)
        ) {
            // If all checks pass, return the ERC1271 magic value for a valid signature
            return 0x1626ba7e;
        } else {
            // If any check fails, return the failure magic value
            return 0xffffffff;
        }
    }

    /// @dev Check if the current caller is authorized or no to perform the call
    /// @return True if the caller is authorized, otherwise false
    function _checkCaller() internal returns (bool) {
        if (_validCaller(msg.sender, msg.data)) {
            return true;
        }
        bytes4 sig = msg.sig;
        ExecutionDetail storage detail = getKernelStorage().execution[sig];
        if (
            address(detail.validator) == address(0)
                || (ValidUntil.unwrap(detail.validUntil) != 0 && ValidUntil.unwrap(detail.validUntil) < block.timestamp)
                || ValidAfter.unwrap(detail.validAfter) > block.timestamp
        ) {
            return false;
        } else {
            return detail.validator.validCaller(msg.sender, msg.data);
        }
    }

    /// @dev This function will validate user operation and be called by EntryPoint
    /// @param _op The user operation to be validated
    /// @param _opHash The hash of the user operation
    /// @param _missingFunds The funds needed to be reimbursed
    function _validateUserOp(UserOperation calldata _op, bytes32 _opHash, uint256 _missingFunds)
        internal
        virtual
        returns (ValidationData)
    {
        // Replace the user op in memory to update the signature
        UserOperation memory op = _op;
        // Remove the validation mode flag from the signature
        op.signature = _op.signature[4:];

        IKernelValidator validator;
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        return IKernelValidator(validator).validateUserOp(op, _opHash, _missingFunds);
    }

    /// @dev This function will validate a signature for the given kernel
    /// @param _hash The hash of the data that was signed
    /// @param _signature The signature to be validated
    /// @return The magic value 0x1626ba7e if the signature is valid, otherwise returns 0xffffffff.
    function _validateSignature(address _requestor, bytes32 _hash, bytes32 _rawHash, bytes calldata _signature)
        internal
        view
        virtual
        returns (ValidationData)
    {
        address validator;
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        // 20 bytes added at the end of the signature to store the address of the caller
        (bool success, bytes memory res) = validator.staticcall(
            abi.encodePacked(
                abi.encodeWithSelector(IKernelValidator.validateSignature.selector, _hash, _signature),
                _rawHash,
                _requestor
            )
        );
        require(success, "Kernel::_validateSignature: failed to validate signature");
        return abi.decode(res, (ValidationData));
    }

    /// @dev Check if the given caller is valid for the given data
    /// @param _caller The caller to be checked
    /// @param _data The data to be checked
    /// @return True if the caller is valid, otherwise false
    function _validCaller(address _caller, bytes calldata _data) internal virtual returns (bool) {
        address validator;
        assembly {
            // Load the validator from the storage slot
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        return IKernelValidator(validator).validCaller(_caller, _data);
    }
}
