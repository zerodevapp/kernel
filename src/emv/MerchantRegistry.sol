// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {Ownable} from "solady/auth/Ownable.sol";

/**
 * @title MerchantRegistry
 * @dev Registry for approved merchants with their corresponding addresses
 * @notice Only the owner can add/remove merchants, ensuring secure merchant validation
 */
contract MerchantRegistry is Ownable {
    
    // Mapping from merchant ID (15 bytes) to their approved address
    mapping(bytes15 => address) public merchantAddresses;
    
    // Events
    event MerchantRegistered(bytes15 indexed merchantId, address indexed merchantAddress);
    event MerchantRemoved(bytes15 indexed merchantId);
    
    // Errors
    error InvalidMerchantId();

    constructor() {
        _initializeOwner(msg.sender);
    }

    /**
     * @dev Modify a merchant's address (register, update, or remove)
     * @param merchantId The 15-byte merchant ID from EMV data (9F16)
     * @param merchantAddress The address to receive payments for this merchant
     *                        Use address(0) to remove/unregister the merchant
     */
    function modifyMerchant(bytes15 merchantId, address merchantAddress) external onlyOwner {
        if (merchantId == bytes15(0)) revert InvalidMerchantId();
        
        merchantAddresses[merchantId] = merchantAddress;
        
        if (merchantAddress == address(0)) {
            // Removing merchant
            emit MerchantRemoved(merchantId);
        } else {
            // Adding or updating merchant
            emit MerchantRegistered(merchantId, merchantAddress);
        }
    }

    /**
     * @dev Get the registered address for a merchant ID
     * @param merchantId The merchant ID to look up
     * @return merchantAddress The registered address (address(0) if not registered)
     */
    function getMerchantAddress(bytes15 merchantId) external view returns (address) {
        return merchantAddresses[merchantId];
    }

    /**
     * @dev Check if a merchant is registered
     * @param merchantId The merchant ID to check
     * @return isRegistered True if the merchant is registered
     */
    function isMerchantRegistered(bytes15 merchantId) external view returns (bool) {
        return merchantAddresses[merchantId] != address(0);
    }

    /**
     * @dev Batch modify multiple merchants
     * @param merchantIds Array of merchant IDs
     * @param addresses Array of corresponding addresses (use address(0) to remove)
     */
    function batchModifyMerchants(bytes15[] calldata merchantIds, address[] calldata addresses) external onlyOwner {
        require(merchantIds.length == addresses.length, "MerchantRegistry: array length mismatch");
        
        for (uint256 i = 0; i < merchantIds.length; i++) {
            bytes15 merchantId = merchantIds[i];
            address merchantAddress = addresses[i];
            
            if (merchantId == bytes15(0)) revert InvalidMerchantId();
            
            merchantAddresses[merchantId] = merchantAddress;
            
            if (merchantAddress == address(0)) {
                // Removing merchant
                emit MerchantRemoved(merchantId);
            } else {
                // Adding or updating merchant
                emit MerchantRegistered(merchantId, merchantAddress);
            }
        }
    }

    /**
     * @dev Get multiple merchant addresses at once
     * @param merchantIds Array of merchant IDs to look up
     * @return addresses Array of corresponding addresses
     */
    function getMerchantAddresses(bytes15[] calldata merchantIds) external view returns (address[] memory addresses) {
        addresses = new address[](merchantIds.length);
        for (uint256 i = 0; i < merchantIds.length; i++) {
            addresses[i] = merchantAddresses[merchantIds[i]];
        }
        return addresses;
    }
}
