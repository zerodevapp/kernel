// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {RsaVerifyOptimized} from "../../lib/SolRsaVerify/src/RsaVerifyOptimized.sol";
import {IValidator, IExecutor, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";
import {MerchantRegistry} from "./MerchantRegistry.sol";
import {EMVSettlement} from "./EMVSettlement.sol";
import {ExecLib} from "../utils/ExecLib.sol";
import {ExecMode, CallType} from "../types/Types.sol";

// Simple IERC20 interface for transfers
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

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
    bytes terminalId;           // 9F1C - Terminal ID (8 bytes)
    bytes merchantId;           // 9F16 - Merchant ID (15 bytes)
    bytes signature;            // 9F4B - RSA signature
    bytes exponent;             // RSA public key exponent
    bytes modulus;              // RSA public key modulus
}

/**
 * @title EMVValidator
 * @dev Complete ERC-7579 module for EMV CDA validation and ERC20 execution
 * @notice Validates EMV CDA signatures and executes ERC20 transfers with merchant registry integration
 */
contract EMVValidator is IValidator {
    // ========== EVENTS ==========
    
    event EMVSignatureValidated(address indexed kernel, bool success);
    event UnpredictableNumberUsed(address indexed kernel, bytes4 unpredictableNumber);
    event ATCIncremented(address indexed kernel, uint16 newATC);

    // ========== STORAGE ==========
    
    struct EMVValidatorStorage {
        mapping(uint32 => bool) usedUnpredictableNumbers;  // Track used unpredictable numbers (4 bytes)
        uint16 expectedATC;  // Next expected ATC value for this kernel instance
    }
    
    mapping(address => EMVValidatorStorage) public emvValidatorStorage;
    address public immutable target;               // Expected target address for validation
    bytes4 public immutable selector;              // Expected function selector for validation

    // ========== ERRORS ==========
    
    error InvalidEMVDataLength(string field, uint256 expected, uint256 actual);
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidCurrencyCode(uint16 currency);
    error InvalidConfig();
    error ModuleNotInstalled();
    error InvalidTarget(address expected, address actual);
    error InvalidFunctionSelector(bytes4 expected, bytes4 actual);

    // ========== CONSTRUCTOR ==========
    
    /**
     * @dev Constructor to initialize immutable values
     * @param _target The target address for validation
     * @param _selector The function selector for validation
     */
    constructor(address _target, bytes4 _selector) {
        if (_target == address(0) || _selector == bytes4(0)) {
            revert InvalidConfig();
        }
        target = _target;
        selector = _selector;
    }

    // ========== MODULE LIFECYCLE ==========

    /**
     * @dev Install the module with ATC configuration
     * @param _data Encoded configuration: abi.encode(atc)
     */
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length == 0) {
            revert InvalidConfig();
        }
        
        uint16 atc = abi.decode(_data, (uint16));
        emvValidatorStorage[msg.sender].expectedATC = atc;
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        // Reset ATC counter for this account
        emvValidatorStorage[msg.sender].expectedATC = 0;
        // Note: usedUnpredictableNumbers entries remain for security
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        // Module is considered initialized if the account has been configured
        // Check if ATC has been set (non-zero) or if there are used unpredictable numbers
        return emvValidatorStorage[smartAccount].expectedATC > 0;
    }

    // ========== VALIDATOR FUNCTIONS ==========

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
        // Validate that this EMV signature is being used for the correct target and function
        _validateTargetAndSelector(userOp.callData);
        
        // Directly validate without external call to preserve msg.sender context
        EMVTransactionData memory txnData = abi.decode(userOp.signature, (EMVTransactionData));
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Validate replay protection and ATC sequence
        _validateReplayProtection(txnData);
        
        // Verify RSA signature using PKCS#1 v1.5 with SHA-256
        bool isValid = _verifyEMVSignature(txnData);
        
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
     * @dev Main EMV CDA signature verification function
     * @param emvData Encoded EMV transaction data
     * @return true if signature is valid, false otherwise
     */
    function verifyEMVSignature(bytes calldata emvData) external returns (bool) {
        EMVTransactionData memory txnData = abi.decode(emvData, (EMVTransactionData));
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Validate replay protection and ATC sequence
        _validateReplayProtection(txnData);
        
        // Verify RSA signature
        bool isValid = _verifyEMVSignature(txnData);
        
        if (isValid) {
            // Update state only if signature is valid
            _updateTransactionState(txnData);
        }
        
        emit EMVSignatureValidated(msg.sender, isValid);
        return isValid;
    }

    /**
     * @dev View-only EMV CDA signature verification (no state changes)
     * @param emvData Encoded EMV transaction data
     * @return true if signature is valid, false otherwise
     */
    function verifyEMVSignatureView(bytes calldata emvData) external view returns (bool) {
        EMVTransactionData memory txnData = abi.decode(emvData, (EMVTransactionData));
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[msg.sender];
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Check unpredictable number hasn't been used
        uint32 unpredictableNumber = uint32(bytes4(txnData.unpredictableNumber));
        if (accountStorage.usedUnpredictableNumbers[unpredictableNumber]) {
            return false; // Already used
        }
        
        // Check ATC sequence
        uint16 receivedATC = uint16(bytes2(txnData.atc));
        if (receivedATC != accountStorage.expectedATC) {
            return false; // Invalid sequence
        }
        
        // Verify RSA signature
        return _verifyEMVSignature(txnData);
    }



    /**
     * @dev Get the configured target and selector
     * @return targetAddress The target address for validation
     * @return functionSelector The function selector for validation
     */
    function getValidationConfig() external view returns (address targetAddress, bytes4 functionSelector) {
        return (target, selector);
    }

    /**
     * @dev Get the EMV storage for a specific account
     * @param account The smart account address
     * @return expectedATC The next expected ATC value
     */
    function getEMVStorage(address account) external view returns (uint16 expectedATC) {
        return emvValidatorStorage[account].expectedATC;
    }

    /**
     * @dev Check if an unpredictable number has been used for a specific account
     * @param account The smart account address
     * @param unpredictableNumber The unpredictable number to check
     * @return used True if the unpredictable number has been used
     */
    function isUnpredictableNumberUsed(address account, bytes4 unpredictableNumber) external view returns (bool used) {
        return emvValidatorStorage[account].usedUnpredictableNumbers[uint32(unpredictableNumber)];
    }

    // ========== INTERNAL VALIDATION FUNCTIONS ==========

    /**
     * @dev Validate that the callData is calling the expected target and function
     * @param callData The callData from the PackedUserOperation
     */
    function _validateTargetAndSelector(bytes calldata callData) internal view {        
        bytes4 actualSelector = bytes4(callData[0:4]);
        if (actualSelector != selector) {
            revert InvalidFunctionSelector(selector, actualSelector);
        }
        
        // Parse execute(ExecMode, bytes) call data structure:
        // selector(4) + execMode(32) + offset(32) + length(32) + executionCalldata(variable)
        
        // Get offset to executionCalldata (should be 0x40 = 64)
        uint256 executionDataOffset = uint256(bytes32(callData[36:68]));
        
        // ExecutionCalldata starts at: 4 + offset + 32 (skip length field)
        uint256 executionDataStart = 4 + executionDataOffset + 32;
        
        // Extract target address from the beginning of executionCalldata (encodeSingle format)
        // encodeSingle format: target(20) + value(32) + calldata(variable)
        if (callData.length >= executionDataStart + 20) {
            address actualTarget = address(bytes20(callData[executionDataStart:executionDataStart + 20]));
            if (actualTarget != target) {
                revert InvalidTarget(target, actualTarget);
            }
        } else {
            revert InvalidTarget(target, address(0));
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
            revert InvalidCurrencyCode(currency);
        }
    }
    
    /**
     * @dev Validate replay protection and ATC sequence
     * @param txnData Transaction data to validate
     */
    function _validateReplayProtection(EMVTransactionData memory txnData) internal view {
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[msg.sender];
        
        // Check unpredictable number hasn't been used
        uint32 unpredictableNumber = uint32(bytes4(txnData.unpredictableNumber));
        if (accountStorage.usedUnpredictableNumbers[unpredictableNumber]) {
            revert UnpredictableNumberAlreadyUsed(bytes4(txnData.unpredictableNumber));
        }
        
        // Check ATC sequence
        uint16 receivedATC = uint16(bytes2(txnData.atc));
        if (receivedATC != accountStorage.expectedATC) {
            revert InvalidATCSequence(accountStorage.expectedATC, receivedATC);
        }
    }
    
    /**
     * @dev Update transaction state after successful validation
     * @param txnData Transaction data that was validated
     */
    function _updateTransactionState(EMVTransactionData memory txnData) internal {
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[msg.sender];
        
        // Mark unpredictable number as used
        uint32 unpredictableNumber = uint32(bytes4(txnData.unpredictableNumber));
        accountStorage.usedUnpredictableNumbers[unpredictableNumber] = true;
        
        // Increment expected ATC
        accountStorage.expectedATC++;
        
        // Emit events
        emit UnpredictableNumberUsed(msg.sender, bytes4(txnData.unpredictableNumber));
        emit ATCIncremented(msg.sender, accountStorage.expectedATC);
    }

    /**
     * @dev Assemble EMV dynamic data according to Book 2, Annex C.5 (Signed Data Format 3)
     * Format: header(0x6A) + format(0x03) + ARQC + UnpredictableNumber + ATC + 
     *         Amount + Currency + Date + TxnType + TVR + CVMResults + TerminalId + MerchantId + trailer(0xBC)
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
            txnData.terminalId,              // 9F1C - Terminal ID (8 bytes)
            txnData.merchantId,              // 9F16 - Merchant ID (15 bytes)
            bytes1(0xBC)                     // Trailer
        );
    }

    /**
     * @dev Verify EMV RSA signature using PKCS#1 v1.5 with SHA-256
     * @param txnData Transaction data containing signature and keys
     * @return true if signature is valid, false otherwise
     */
    function _verifyEMVSignature(EMVTransactionData memory txnData) internal view returns (bool) {
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

}
