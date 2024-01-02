// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {StealthAggreagteSignature} from "./StealthAggreagteSignature.sol";
import {IKernelValidator} from "../../interfaces/IKernelValidator.sol";
import {ValidationData} from "../../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../../common/Constants.sol";

/**
 * @dev Storage structure for Stealth Address Registry Module.
 * StealthPubkey, dhkey are used in aggregated signature.
 * EphemeralPubkey is used to recover private key of stealth address.
 */
struct StealthAddressValidatorStorage {
    uint256 stealthPubkey;
    uint256 dhkey;
    uint256 ephemeralPubkey;
    address stealthAddress;
    uint8 stealthPubkeyPrefix;
    uint8 dhkeyPrefix;
    uint8 ephemeralPrefix;
}

/**
 * @author Justin Zen - <justin@moonchute.xyz>
 * @title Stealth Address Validator for ZeroDev Kernel.
 * @notice This validator uses the Stealth address to validate signatures.
 */
contract StealthAddressValidator is IKernelValidator, EIP712 {
    /// @notice The type hash used for kernel user op validation
    bytes32 constant USER_OP_TYPEHASH =
        keccak256("AllowUserOp(address owner,address kernelWallet,bytes32 userOpHash)");
    /// @notice The type hash used for kernel signature validation
    bytes32 constant SIGNATURE_TYPEHASH =
        keccak256("KernelSignature(address owner,address kernelWallet,bytes32 hash)");

    /// @notice Emitted when the stealth address of a kernel is changed.
    event StealthAddressChanged(
        address indexed kernel, address indexed oldStealthAddress, address indexed newStealthAddress
    );

    /* -------------------------------------------------------------------------- */
    /*                                   Storage                                  */
    /* -------------------------------------------------------------------------- */
    mapping(address => StealthAddressValidatorStorage) public stealthAddressValidatorStorage;

    /* -------------------------------------------------------------------------- */
    /*                               EIP-712 Methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the current name & version of the validator, used for the EIP-712 domain separator from Solady
    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Kernel:StealthAddressValidator", "1.0.0");
    }

    /// @dev Tell to solady that the current name & version of the validator won't change, so no need to recompute the eip-712 domain separator
    function _domainNameAndVersionMayChange() internal pure override returns (bool) {
        return false;
    }

    /// @dev Export the current domain seperator
    function getDomainSeperator() public view returns (bytes32) {
        return _domainSeparator();
    }

    /* -------------------------------------------------------------------------- */
    /*                          Kernel validator Methods                          */
    /* -------------------------------------------------------------------------- */

    /// @dev Enable this validator for a given `kernel` (msg.sender)
    function enable(bytes calldata _data) external payable override {
        address stealthAddress = address(bytes20(_data[0:20]));
        uint256 stealthAddressPubkey = uint256(bytes32(_data[20:52]));
        uint256 stealthAddressDhkey = uint256(bytes32(_data[52:84]));
        uint8 stealthAddressPubkeyPrefix = uint8(_data[84]);
        uint8 stealthAddressDhkeyPrefix = uint8(_data[85]);
        uint256 ephemeralPubkey = uint256(bytes32(_data[86:118]));
        uint8 ephemeralPrefix = uint8(_data[118]);

        address oldStealthAddress = stealthAddressValidatorStorage[msg.sender].stealthAddress;
        stealthAddressValidatorStorage[msg.sender] = StealthAddressValidatorStorage({
            stealthPubkey: stealthAddressPubkey,
            dhkey: stealthAddressDhkey,
            ephemeralPubkey: ephemeralPubkey,
            stealthAddress: stealthAddress,
            stealthPubkeyPrefix: stealthAddressPubkeyPrefix,
            dhkeyPrefix: stealthAddressDhkeyPrefix,
            ephemeralPrefix: ephemeralPrefix
        });
        emit StealthAddressChanged(msg.sender, oldStealthAddress, stealthAddress);
    }

    /// @dev Disable this validator for a given `kernel` (msg.sender)
    function disable(bytes calldata) external payable override {
        address stealthAddress;
        delete stealthAddressValidatorStorage[msg.sender];
        emit StealthAddressChanged(msg.sender, stealthAddress, address(0));
    }

    /// @dev Validate a `_userOp` using a EIP-712 signature, signed by the owner of the kernel account who is the `_userOp` sender
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        bytes1 mode = _userOp.signature[0];
        StealthAddressValidatorStorage storage stealthData = stealthAddressValidatorStorage[_userOp.sender];
        address stealthAddress = stealthData.stealthAddress;
        bytes32 typedDataHash =
            _hashTypedData(keccak256(abi.encode(USER_OP_TYPEHASH, stealthAddress, _userOp.sender, _userOpHash)));

        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            return stealthAddress == ECDSA.recover(typedDataHash, _userOp.signature[1:])
                ? ValidationData.wrap(0)
                : SIG_VALIDATION_FAILED;
        } else if (mode == 0x01) {
            return StealthAggreagteSignature.validateAggregatedSignature(
                stealthData.stealthPubkey,
                stealthData.dhkey,
                stealthData.stealthPubkeyPrefix,
                stealthData.dhkeyPrefix,
                typedDataHash,
                _userOp.signature[1:]
            ) ? ValidationData.wrap(0) : SIG_VALIDATION_FAILED;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    /// @dev Validate a `_signature` of the `_hash` ofor the given `kernel` (msg.sender)
    function validateSignature(bytes32 _hash, bytes calldata _signature)
        external
        view
        override
        returns (ValidationData validationData)
    {
        bytes1 mode = _signature[0];
        StealthAddressValidatorStorage storage stealthData = stealthAddressValidatorStorage[msg.sender];
        address stealthAddress = stealthData.stealthAddress;
        bytes32 typedDataHash =
            _hashTypedData(keccak256(abi.encode(SIGNATURE_TYPEHASH, stealthAddress, msg.sender, _hash)));

        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            return stealthAddress == ECDSA.recover(typedDataHash, _signature[1:])
                ? ValidationData.wrap(0)
                : SIG_VALIDATION_FAILED;
        } else if (mode == 0x01) {
            return StealthAggreagteSignature.validateAggregatedSignature(
                stealthData.stealthPubkey,
                stealthData.dhkey,
                stealthData.stealthPubkeyPrefix,
                stealthData.dhkeyPrefix,
                typedDataHash,
                _signature[1:]
            ) ? ValidationData.wrap(0) : SIG_VALIDATION_FAILED;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    /// @dev Check if the caller is a valid signer for this kernel account
    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return stealthAddressValidatorStorage[msg.sender].stealthAddress == _caller;
    }

    /* -------------------------------------------------------------------------- */
    /*                             Public view methods                            */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the owner of a given `kernel`
    function getOwner(address _kernel) public view returns (address) {
        return stealthAddressValidatorStorage[_kernel].stealthAddress;
    }
}
