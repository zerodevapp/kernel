// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {MerchantRegistry} from "./MerchantRegistry.sol";
import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_EXECUTOR
} from "../types/Constants.sol";
import {EMVTransactionData, IERC20} from "./EMVValidator.sol";
import {SafeTransferLib} from "lib/solady/src/utils/SafeTransferLib.sol";

/**
 * @title EMVSettlement
 * @dev Handles EMV transaction settlement and ERC20 token transfers
 * @notice Processes EMV transaction data and executes corresponding token transfers
 */
contract EMVSettlement is IExecutor {
    // ========== EVENTS ==========
    
    event EMVTransferExecuted(
        address indexed from,
        address indexed to,
        address indexed token,
        uint256 amount,
        bytes4 unpredictableNumber,
        uint16 atc
    );
    event EMVSettlementConfigured(address indexed account, address token, address recipient);

    // ========== STORAGE ==========
    
    // Immutable configuration - accessible in both regular call and delegate call contexts
    address public immutable configuredToken;      // ERC20 token address for this settlement instance
    MerchantRegistry public immutable merchantRegistry; // Registry for merchant address validation
    uint8 public immutable decimals;                   // Token decimals for amount conversion

    // ========== CONSTRUCTOR ==========
    
    constructor(address _tokenAddress, address _merchantRegistryAddress, uint8 _decimals) {
        if (_tokenAddress == address(0) || _merchantRegistryAddress == address(0)) {
            revert InvalidConfig();
        }
        
        if (_decimals < 2) {
            revert InvalidDecimals();
        }
        
        configuredToken = _tokenAddress;
        merchantRegistry = MerchantRegistry(_merchantRegistryAddress);
        decimals = _decimals;
    }

    // ========== ERRORS ==========
    
    error TransferFailed();
    error InvalidAmount();
    error TokenNotConfigured();
    error MerchantNotRegistered(bytes15 merchantId);
    error MerchantRegistryNotSet();
    error InvalidConfig();
    error ModuleNotInstalled();
    error InvalidDecimals();



    // ========== MODULE LIFECYCLE ==========

    /**
     * @dev Install the module
     * @param data Installation data: abi.encode(tokenAddress, merchantRegistryAddress, decimals)
     */
    function onInstall(bytes calldata data) external payable override {
        // Configuration is set in constructor as immutable values
        // This function is called during module installation but config is already set
        emit EMVSettlementConfigured(msg.sender, configuredToken, address(0));
    }

    /**
     * @dev Uninstall the module
     * @param data Uninstallation data (not used for this contract)
     */
    function onUninstall(bytes calldata data) external payable override {
        // Configuration is immutable, nothing to clean up
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view override returns (bool) {
        // Configuration is immutable and set in constructor, so always initialized
        return configuredToken != address(0) && address(merchantRegistry) != address(0) && decimals >= 2;
    }

    // ========== SETTLEMENT FUNCTIONS ==========

    /**
     * @dev Main entry point: Execute EMV-based ERC20 transfer using validated EMV data
     * @param emvData Encoded EMV transaction data (should be same as from UserOp signature)
     */
    function execute(bytes calldata emvData) external payable {
        // Decode EMV transaction data
        EMVTransactionData memory txnData = abi.decode(emvData, (EMVTransactionData));

        // Extract amount from EMV BCD format (6 bytes) using immutable decimals
        uint256 transferAmount = _extractAmountFromBCD(txnData.amount, decimals);

        if (transferAmount == 0) {
            revert InvalidAmount();
        }
        
        bytes15 merchantId = bytes15(txnData.merchantId);
        address recipient = merchantRegistry.getMerchantAddress(merchantId);
        
        if (recipient == address(0)) {
            revert MerchantNotRegistered(bytes15(txnData.merchantId));
        }

        // Execute ERC20 transfer (in delegate call context, address(this) is the kernel)
        SafeTransferLib.safeTransfer(configuredToken,recipient, transferAmount);

        // Emit event with EMV details
        emit EMVTransferExecuted(
            address(this), // In delegate call context, address(this) is the kernel
            recipient,
            configuredToken,
            transferAmount,
            bytes4(txnData.unpredictableNumber),
            uint16(bytes2(txnData.atc))
        );
    }



    // ========== CONFIGURATION FUNCTIONS ==========

    /**
     * @dev Get the configured token, merchant registry, and decimals
     * @return tokenAddress The configured ERC20 token address
     * @return registry The merchant registry address
     * @return tokenDecimals The configured token decimals
     */
    function getSettlementConfig() external view returns (address tokenAddress, address registry, uint8 tokenDecimals) {
        return (configuredToken, address(merchantRegistry), decimals);
    }

    // ========== INTERNAL FUNCTIONS ==========

    /**
     * @dev Extract amount from EMV BCD format
     * @param bcdAmount 6-byte BCD encoded amount
     * @param tokenDecimals Number of decimals for the token
     * @return Amount in token units based on provided decimals
     */
    function _extractAmountFromBCD(bytes memory bcdAmount, uint8 tokenDecimals) internal pure returns (uint256) {
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
        
        // Convert from cents to token units using provided decimals
        // EMV amounts are typically in cents (2 decimal places)
        // So we need to convert: cents -> token units
        // Example: If token has 18 decimals, multiply by 10^(18-2) = 10^16
        if (tokenDecimals < 2) {
            return 0; // Invalid decimals
        }
        return amount * 10**(tokenDecimals - 2);
    }
}
