// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {RsaVerifyOptimized} from "../../lib/SolRsaVerify/src/RsaVerifyOptimized.sol";
import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";

/**
 * @title EMVValidator
 * @dev ERC-7579 Module for EMV Combined Dynamic Data Authentication (CDA) signature validation
 * @notice This module validates EMV CDA signatures (tag 9F4B) using PKCS#1 v1.5 with SHA-256
 */


struct EMVTransactionData {
    bytes arqc;                 // 9F26 - Application Cryptogram (8 bytes)
    bytes unpredictableNumber;  // 9F37 - 4 bytes from terminal
    bytes atc;                  // 9F36 - 2-byte Application Transaction Counter
    bytes amount;               // 9F02 - 6-byte BCD amount
    bytes currency;             // 5F2A - 2-byte ISO currency code (big-endian)
    bytes date;                 // 9A - YYMMDD (3 bytes BCD)
    bytes txnType;              // 9C - 1 byte transaction type
    bytes tvr;                  // 95 - 5 bytes Terminal Verification Results
    bytes cvmResults;           // 9F34 - 3 bytes CVM Results
    bytes signature;            // 9F4B - RSA signature
    bytes exponent;             // RSA public key exponent
    bytes modulus;              // RSA public key modulus
}

contract EMVValidator is IValidator, IHook {
    event EMVSignatureValidated(address indexed kernel, bool success);
    event UnpredictableNumberUsed(address indexed kernel, bytes4 unpredictableNumber);
    event ATCIncremented(address indexed kernel, uint16 newATC);

    mapping(bytes32 => bool) public usedUnpredictableNumbers;  // keccak256(abi.encode(address, unpredictableNumber))
    mapping(address => uint16) public expectedATC;  // Next expected ATC value for each address

    error InvalidEMVDataLength(string field, uint256 expected, uint256 actual);
    error EMVValidationFailed();
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidCurrencyCode(uint16 currency);

    /**
     * @dev Install the module
     * @param _data Unused - RSA keys are provided per transaction
     */
    function onInstall(bytes calldata _data) external payable override {
        // Initialize ATC counter to 0 for this address
        expectedATC[msg.sender] = 0;
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        // Reset ATC counter
        delete expectedATC[msg.sender];
        // Note: usedUnpredictableNumbers entries remain for security
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view override returns (bool) {
        // Module is considered initialized if ATC tracking exists
        return expectedATC[smartAccount] >= 0; // Always true for uint16, but explicit for clarity
    }

    /**
     * @dev Validate EMV CDA signature for ERC-4337 user operation
     * @param userOp The user operation containing EMV transaction data in signature field
     * @param userOpHash The hash of the user operation
     * @return SIG_VALIDATION_SUCCESS_UINT if valid, SIG_VALIDATION_FAILED_UINT otherwise
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        // Directly validate without external call to preserve msg.sender context
        EMVTransactionData memory txnData = abi.decode(userOp.signature, (EMVTransactionData));
        
        // Validate field lengths according to EMV specification
        _validateEMVFieldLengths(txnData);
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Validate replay protection and ATC sequence
        _validateReplayProtection(txnData);
        
        // Assemble dynamic data according to EMV Book 2, Annex C.5 (Signed Data Format 3)
        bytes memory dynamicData = _assembleDynamicData(txnData);
        
        // Verify RSA signature using PKCS#1 v1.5 with SHA-256
        bool isValid = RsaVerifyOptimized.pkcs1Sha256Raw(
            dynamicData,
            txnData.signature,
            txnData.exponent,
            txnData.modulus
        );
        
        if (isValid) {
            // Update state only if signature is valid
            _updateTransactionState(txnData);
            emit EMVSignatureValidated(msg.sender, true);
            return SIG_VALIDATION_SUCCESS_UINT;
        } else {
            emit EMVSignatureValidated(msg.sender, false);
            return SIG_VALIDATION_FAILED_UINT;
        }
    }

    /**
     * @dev Validate EMV signature for ERC-1271 (view-only, no state changes)
     * @param hash The hash to validate
     * @param sig The signature data containing EMV transaction data
     * @return ERC1271_MAGICVALUE if valid, ERC1271_INVALID otherwise
     */
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        try this.verifyEMVSignatureView(sig) returns (bool success) {
            if (success) {
                return ERC1271_MAGICVALUE;
            }
        } catch {
            // Validation failed
        }
        
        return ERC1271_INVALID;
    }

    /**
     * @dev View-only EMV CDA signature verification (no state changes)
     * @param emvData Encoded EMV transaction data
     * @return true if signature is valid, false otherwise
     */
    function verifyEMVSignatureView(bytes calldata emvData) external view returns (bool) {
        EMVTransactionData memory txnData = abi.decode(emvData, (EMVTransactionData));
        
        // Validate field lengths according to EMV specification
        _validateEMVFieldLengths(txnData);
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Check unpredictable number hasn't been used
        bytes32 unpredictableKey = keccak256(abi.encode(msg.sender, txnData.unpredictableNumber));
        if (usedUnpredictableNumbers[unpredictableKey]) {
            return false; // Already used
        }
        
        // Check ATC sequence
        uint16 receivedATC = uint16(bytes2(txnData.atc));
        if (receivedATC != expectedATC[msg.sender]) {
            return false; // Invalid sequence
        }
        
        // Assemble dynamic data according to EMV Book 2, Annex C.5 (Signed Data Format 3)
        bytes memory dynamicData = _assembleDynamicData(txnData);
        
        // Verify RSA signature using PKCS#1 v1.5 with SHA-256
        return RsaVerifyOptimized.pkcs1Sha256Raw(
            dynamicData,
            txnData.signature,
            txnData.exponent,
            txnData.modulus
        );
    }

    /**
     * @dev Pre-execution hook - validates EMV signature before transaction
     */
    function preCheck(address msgSender, uint256 value, bytes calldata data)
        external
        payable
        override
        returns (bytes memory)
    {
        // For EMV validator, we can perform additional checks here if needed
        // For now, we'll just return empty data as the main validation happens in validateUserOp
        return hex"";
    }

    /**
     * @dev Post-execution hook - currently no post-execution logic needed
     */
    function postCheck(bytes calldata hookData) external payable override {
        // No post-execution logic needed for EMV validation
    }

    /**
     * @dev Main EMV CDA signature verification function
     * @param emvData Encoded EMV transaction data
     * @return true if signature is valid, false otherwise
     */
    function verifyEMVSignature(bytes calldata emvData) external returns (bool) {
        EMVTransactionData memory txnData = abi.decode(emvData, (EMVTransactionData));
        
        // Validate field lengths according to EMV specification
        _validateEMVFieldLengths(txnData);
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Validate replay protection and ATC sequence
        _validateReplayProtection(txnData);
        
        // Assemble dynamic data according to EMV Book 2, Annex C.5 (Signed Data Format 3)
        bytes memory dynamicData = _assembleDynamicData(txnData);
        
        // Verify RSA signature using PKCS#1 v1.5 with SHA-256
        bool isValid = RsaVerifyOptimized.pkcs1Sha256Raw(
            dynamicData,
            txnData.signature,
            txnData.exponent,
            txnData.modulus
        );
        
        if (isValid) {
            // Update state only if signature is valid
            _updateTransactionState(txnData);
        }
        
        emit EMVSignatureValidated(msg.sender, isValid);
        return isValid;
    }

    /**
     * @dev Public interface for EMV signature verification with explicit parameters
     * @param arqc Application Cryptogram (9F26) - 8 bytes
     * @param unpredictableNumber Unpredictable Number (9F37) - 4 bytes
     * @param atc Application Transaction Counter (9F36) - 2 bytes
     * @param amount Amount (9F02) - 6 bytes BCD
     * @param currency Currency (5F2A) - 2 bytes
     * @param date Date (9A) - 3 bytes BCD YYMMDD
     * @param txnType Transaction Type (9C) - 1 byte
     * @param tvr Terminal Verification Results (95) - 5 bytes
     * @param cvmResults CVM Results (9F34) - 3 bytes
     * @param signature RSA signature (9F4B)
     * @param exponent RSA public key exponent
     * @param modulus RSA public key modulus
     * @return true if signature is valid, false otherwise
     */
    function verify9F4B(
        bytes calldata arqc,
        bytes calldata unpredictableNumber,
        bytes calldata atc,
        bytes calldata amount,
        bytes calldata currency,
        bytes calldata date,
        bytes calldata txnType,
        bytes calldata tvr,
        bytes calldata cvmResults,
        bytes calldata signature,
        bytes calldata exponent,
        bytes calldata modulus
    ) external view returns (bool) {
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: arqc,
            unpredictableNumber: unpredictableNumber,
            atc: atc,
            amount: amount,
            currency: currency,
            date: date,
            txnType: txnType,
            tvr: tvr,
            cvmResults: cvmResults,
            signature: signature,
            exponent: exponent,
            modulus: modulus
        });
        
        // Validate field lengths
        _validateEMVFieldLengths(txnData);
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Assemble dynamic data
        bytes memory dynamicData = _assembleDynamicData(txnData);
        
        // Verify signature
        return RsaVerifyOptimized.pkcs1Sha256Raw(
            dynamicData,
            signature,
            exponent,
            modulus
        );
    }

    /**
     * @dev Validate EMV field lengths according to specification
     */
    function _validateEMVFieldLengths(EMVTransactionData memory txnData) internal pure {
        if (txnData.arqc.length != 8) {
            revert("EMVValidator: invalid ARQC length");
        }
        if (txnData.unpredictableNumber.length != 4) {
            revert("EMVValidator: invalid UnpredictableNumber length");
        }
        if (txnData.atc.length != 2) {
            revert("EMVValidator: invalid ATC length");
        }
        if (txnData.amount.length != 6) {
            revert("EMVValidator: invalid Amount length");
        }
        if (txnData.currency.length != 2) {
            revert("EMVValidator: invalid Currency length");
        }
        if (txnData.date.length != 3) {
            revert("EMVValidator: invalid Date length");
        }
        if (txnData.txnType.length != 1) {
            revert("EMVValidator: invalid TxnType length");
        }
        if (txnData.tvr.length != 5) {
            revert("EMVValidator: invalid TVR length");
        }
        if (txnData.cvmResults.length != 3) {
            revert("EMVValidator: invalid CVMResults length");
        }
        if (txnData.signature.length == 0) {
            revert("EMVValidator: invalid Signature length");
        }
        if (txnData.exponent.length == 0) {
            revert("EMVValidator: invalid Exponent length");
        }
        if (txnData.modulus.length < 128) {
            revert("EMVValidator: invalid Modulus length");
        }
    }

    /**
     * @dev Validate currency code (must be 840 USD or 997 USN)
     * @param txnData Transaction data to validate
     */
    function _validateCurrencyCode(EMVTransactionData memory txnData) internal pure {
        // Currency is stored as 2 bytes big-endian
        uint16 currency = uint16(bytes2(txnData.currency));
        if (currency != 840 && currency != 997) {
            revert("EMVValidator: invalid currency code");
        }
    }
    
    /**
     * @dev Validate replay protection and ATC sequence
     * @param txnData Transaction data to validate
     */
    function _validateReplayProtection(EMVTransactionData memory txnData) internal view {
        // Check unpredictable number hasn't been used
        bytes32 unpredictableKey = keccak256(abi.encode(msg.sender, txnData.unpredictableNumber));
        if (usedUnpredictableNumbers[unpredictableKey]) {
            revert("EMVValidator: unpredictable number already used");
        }
        
        // Check ATC sequence
        uint16 receivedATC = uint16(bytes2(txnData.atc));
        if (receivedATC != expectedATC[msg.sender]) {
            revert("EMVValidator: invalid ATC sequence");
        }
    }
    
    /**
     * @dev Update transaction state after successful validation
     * @param txnData Transaction data that was validated
     */
    function _updateTransactionState(EMVTransactionData memory txnData) internal {
        // Mark unpredictable number as used
        bytes32 unpredictableKey = keccak256(abi.encode(msg.sender, txnData.unpredictableNumber));
        usedUnpredictableNumbers[unpredictableKey] = true;
        
        // Increment expected ATC
        expectedATC[msg.sender]++;
        
        // Emit events
        emit UnpredictableNumberUsed(msg.sender, bytes4(txnData.unpredictableNumber));
        emit ATCIncremented(msg.sender, expectedATC[msg.sender]);
    }

    /**
     * @dev Assemble EMV dynamic data according to Book 2, Annex C.5 (Signed Data Format 3)
     * Format: header(0x6A) + format(0x03) + ARQC + UnpredictableNumber + ATC + 
     *         Amount + Currency + Date + TxnType + TVR + CVMResults + trailer(0xBC)
     */
    function _assembleDynamicData(EMVTransactionData memory txnData) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(0x6A),                    // Header
            bytes1(0x03),                    // Format (Signed Data Format 3)
            txnData.arqc,                    // 9F26 - ARQC (8 bytes)
            txnData.unpredictableNumber,     // 9F37 - Unpredictable Number (4 bytes)
            txnData.atc,                     // 9F36 - ATC (2 bytes)
            txnData.amount,                  // 9F02 - Amount (6 bytes BCD)
            txnData.currency,                // 5F2A - Currency (2 bytes)
            txnData.date,                    // 9A - Date (3 bytes BCD)
            txnData.txnType,                 // 9C - Transaction Type (1 byte)
            txnData.tvr,                     // 95 - TVR (5 bytes)
            txnData.cvmResults,              // 9F34 - CVM Results (3 bytes)
            bytes1(0xBC)                     // Trailer
        );
    }
}
