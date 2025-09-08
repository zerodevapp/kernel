// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {RsaVerifyOptimized} from "../../lib/SolRsaVerify/src/RsaVerifyOptimized.sol";
import {IValidator, IExecutor} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";
import {MerchantRegistry} from "./MerchantRegistry.sol";

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
 * @title EMVProcessor
 * @dev Complete ERC-7579 module for EMV CDA validation and ERC20 execution
 * @notice Validates EMV CDA signatures and executes ERC20 transfers with merchant registry integration
 */
contract EMVProcessor is IValidator, IExecutor {
    // ========== EVENTS ==========
    
    event EMVSignatureValidated(address indexed kernel, bool success);
    event UnpredictableNumberUsed(address indexed kernel, bytes4 unpredictableNumber);
    event ATCIncremented(address indexed kernel, uint16 newATC);
    event EMVTransferExecuted(
        address indexed from,
        address indexed to,
        address indexed token,
        uint256 amount,
        bytes4 unpredictableNumber,
        uint16 atc
    );
    event EMVExecutorConfigured(address indexed account, address token, address recipient);

    // ========== STORAGE ==========
    
    mapping(uint32 => bool) public usedUnpredictableNumbers;  // Track used unpredictable numbers (4 bytes)
    uint16 public expectedATC;  // Next expected ATC value for this kernel instance
    address public configuredToken;      // ERC20 token address for this kernel instance
    address public configuredRecipient;  // Default recipient for this kernel instance
    MerchantRegistry public merchantRegistry; // Registry for merchant address validation

    // ========== ERRORS ==========
    
    error InvalidEMVDataLength(string field, uint256 expected, uint256 actual);
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidCurrencyCode(uint16 currency);
    error TransferFailed();
    error InvalidAmount();
    error TokenNotConfigured();
    error MerchantNotRegistered(bytes15 merchantId);
    error MerchantRegistryNotSet();
    error InvalidConfig();
    error ModuleNotInstalled();

    // ========== MODULE LIFECYCLE ==========

    /**
     * @dev Install the module with optional ERC20 and merchant registry configuration
     * @param _data Optional encoded configuration: 
     *              - abi.encode(tokenAddress, recipient) for basic config
     *              - abi.encode(tokenAddress, recipient, merchantRegistry) for full config
     *              If empty, only validator/hook functionality is enabled
     */
    function onInstall(bytes calldata _data) external payable override {
        (address tokenAddress, address recipient, address registry, uint16 atc) = abi.decode(_data, (address, address, address, uint16));

        if (tokenAddress == address(0) || recipient == address(0) || registry == address(0)) {
            revert InvalidConfig();
        }

        expectedATC = atc;
        configuredToken = tokenAddress;
        configuredRecipient = recipient;
        merchantRegistry = MerchantRegistry(registry);
        emit EMVExecutorConfigured(msg.sender, tokenAddress, recipient);
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        // Reset ATC counter
        expectedATC = 0;
        // Clean up executor configuration
        configuredToken = address(0);
        configuredRecipient = address(0);
        merchantRegistry = MerchantRegistry(address(0));
        // Note: usedUnpredictableNumbers entries remain for security
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        // Module is considered initialized (always true after onInstall is called)
        // In delegate call context, we can't easily track initialization per address
        // This is acceptable since the kernel manages module lifecycle
        return configuredToken != address(0)  && configuredRecipient != address(0) && merchantRegistry != MerchantRegistry(address(0));
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
        
        // Validate currency code
        _validateCurrencyCode(txnData);
        
        // Check unpredictable number hasn't been used
        uint32 unpredictableNumber = uint32(bytes4(txnData.unpredictableNumber));
        if (usedUnpredictableNumbers[unpredictableNumber]) {
            return false; // Already used
        }
        
        // Check ATC sequence
        uint16 receivedATC = uint16(bytes2(txnData.atc));
        if (receivedATC != expectedATC) {
            return false; // Invalid sequence
        }
        
        // Verify RSA signature
        return _verifyEMVSignature(txnData);
    }

    // ========== EXECUTOR FUNCTIONS ==========

    /**
     * @dev Execute EMV-based ERC20 transfer using validated EMV data
     * @param emvData Encoded EMV transaction data (should be same as from UserOp signature)
     * @param customRecipient Optional custom recipient (if zero address, uses merchant registry)
     */
    function executeEMVTransfer(bytes calldata emvData, address customRecipient) external payable {
        if (!_isInitialized(msg.sender)) {
            revert ModuleNotInstalled();
        }

        // Decode EMV transaction data
        EMVTransactionData memory txnData = abi.decode(emvData, (EMVTransactionData));

        // Extract amount from EMV BCD format (6 bytes)
        uint256 transferAmount = _extractAmountFromBCD(txnData.amount);
        if (transferAmount == 0) {
            revert InvalidAmount();
        }

        // Determine recipient using MerchantRegistry
        address recipient;
        if (customRecipient != address(0)) {
            // Use custom recipient if provided
            recipient = customRecipient;
        } else {
            // Look up merchant address from registry
            if (address(merchantRegistry) == address(0)) {
                revert MerchantRegistryNotSet();
            }
            
            bytes15 merchantId = bytes15(txnData.merchantId);
            recipient = merchantRegistry.getMerchantAddress(merchantId);
            
            if (recipient == address(0)) {
                revert MerchantNotRegistered(bytes15(txnData.merchantId));
            }
        }

        // Execute ERC20 transfer
        IERC20 token = IERC20(configuredToken);
        // In delegate call context, address(this) is the kernel, so use transfer instead of transferFrom
        bool success = token.transfer(recipient, transferAmount);
        
        if (!success) {
            revert TransferFailed();
        }

        // Emit event with EMV details
        emit EMVTransferExecuted(
            msg.sender,
            recipient,
            configuredToken,
            transferAmount,
            bytes4(txnData.unpredictableNumber),
            uint16(bytes2(txnData.atc))
        );
    }


    /**
     * @dev Get the configured token, recipient, and merchant registry
     * @return tokenAddress The configured ERC20 token address
     * @return recipient The configured recipient address
     * @return registry The merchant registry address
     */
    function getExecutorConfig() external view returns (address tokenAddress, address recipient, address registry) {
        return (configuredToken, configuredRecipient, address(merchantRegistry));
    }

    /**
     * @dev Update the executor configuration
     * @param tokenAddress New ERC20 token address
     * @param recipient New recipient address
     */
    function updateExecutorConfig(address tokenAddress, address recipient) external {
        configuredToken = tokenAddress;
        configuredRecipient = recipient;
        
        emit EMVExecutorConfigured(msg.sender, tokenAddress, recipient);
    }

    // ========== INTERNAL VALIDATION FUNCTIONS ==========

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
        // Check unpredictable number hasn't been used
        uint32 unpredictableNumber = uint32(bytes4(txnData.unpredictableNumber));
        if (usedUnpredictableNumbers[unpredictableNumber]) {
            revert UnpredictableNumberAlreadyUsed(bytes4(txnData.unpredictableNumber));
        }
        
        // Check ATC sequence
        uint16 receivedATC = uint16(bytes2(txnData.atc));
        if (receivedATC != expectedATC) {
            revert InvalidATCSequence(expectedATC, receivedATC);
        }
    }
    
    /**
     * @dev Update transaction state after successful validation
     * @param txnData Transaction data that was validated
     */
    function _updateTransactionState(EMVTransactionData memory txnData) internal {
        // Mark unpredictable number as used
        uint32 unpredictableNumber = uint32(bytes4(txnData.unpredictableNumber));
        usedUnpredictableNumbers[unpredictableNumber] = true;
        
        // Increment expected ATC
        expectedATC++;
        
        // Emit events
        emit UnpredictableNumberUsed(msg.sender, bytes4(txnData.unpredictableNumber));
        emit ATCIncremented(msg.sender, expectedATC);
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

    /**
     * @dev Extract amount from EMV BCD format
     * @param bcdAmount 6-byte BCD encoded amount
     * @return Amount in wei (assumes 2 decimal places)
     */
    function _extractAmountFromBCD(bytes memory bcdAmount) internal pure returns (uint256) {
        if (bcdAmount.length != 6) {
            return 0;
        }

        uint256 amount = 0;
        for (uint256 i = 0; i < 6; i++) {
            uint8 byte_val = uint8(bcdAmount[i]);
            uint8 high_nibble = byte_val >> 4;
            uint8 low_nibble = byte_val & 0x0F;
            
            // Validate BCD digits (0-9)
            if (high_nibble > 9 || low_nibble > 9) {
                return 0;
            }
            
            amount = amount * 100 + high_nibble * 10 + low_nibble;
        }
        
        // Convert from cents to wei (assuming token has 18 decimals)
        // EMV amounts are typically in cents, so multiply by 10^16 to get wei
        return amount * 10**16;
    }
}
