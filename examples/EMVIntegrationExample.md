# EMVValidator Integration Example

## File Locations
- **Contract**: `src/emv/EMVValidator.sol`
- **Tests**: `test/EMVValidator.t.sol`

## Overview

The EMVValidator is now a complete ERC-7579 module that acts as:
- **Validator**: Validates EMV CDA signatures for transaction authorization
- **Hook**: Provides pre/post execution hooks for additional security
- **Executor**: Extracts EMV transaction data and executes ERC20 transfers

## Complete Flow: EMV Card → ERC20 Transfer

### 1. Installation & Configuration

```solidity
// Install EMVValidator with ERC20 configuration
address usdcToken = 0xA0b86a33E6441E98E6a4B5C8E6a4B5C8E6a4B5C8;
address recipient = 0x742d35Cc9d3E8E3E8E3E8E3E8E3E8E3E8E3E8E3E;

bytes memory installData = abi.encode(usdcToken, recipient);
kernel.installModule(MODULE_TYPE_VALIDATOR, address(emvValidator), installData);
```

### 2. UserOp Construction

```solidity
// EMV data from card transaction (updated with Terminal ID and Merchant ID)
EMVTransactionData memory emvData = EMVTransactionData({
    arqc: hex"1234567890ABCDEF",           // 9F26 - Application Cryptogram (8 bytes)
    unpredictableNumber: hex"12345678",    // 9F37 - Terminal random (4 bytes)
    atc: hex"0000",                        // 9F36 - Transaction counter (2 bytes)
    amount: hex"000000010000",             // 9F02 - $100.00 in BCD (6 bytes)
    currency: hex"0348",                   // 5F2A - USD (840) (2 bytes)
    date: hex"231201",                     // 9A - Dec 1, 2023 (3 bytes)
    txnType: hex"00",                      // 9C - Purchase (1 byte)
    tvr: hex"0000000000",                  // 95 - Terminal results (5 bytes)
    cvmResults: hex"000000",               // 9F34 - CVM results (3 bytes)
    terminalId: hex"5445535430303100",     // 9F1C - Terminal ID (8 bytes) "TEST001"
    merchantId: hex"4D45524348414E5430303132333400", // 9F16 - Merchant ID (15 bytes) "MERCHANT001234"
    signature: rsaSignature,               // 9F4B - EMV signature
    exponent: hex"010001",                 // RSA public key exponent
    modulus: issuerModulus                 // RSA public key modulus
});

// Create UserOp with EMV signature and transfer call
PackedUserOperation memory userOp = PackedUserOperation({
    sender: smartAccount,
    nonce: 0,
    initCode: "",
    callData: abi.encodeWithSelector(
        emvValidator.executeEMVTransfer.selector,
        abi.encode(emvData)
    ),
    accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
    preVerificationGas: 21000,
    gasFees: bytes32(uint256(1000000000) << 128 | uint256(1000000000)),
    paymasterAndData: "",
    signature: abi.encode(emvData)  // EMV data in signature field
});
```

### 3. Validation & Execution Flow

1. **EntryPoint calls `validateUserOp`**:
   ```solidity
   // EMVValidator validates the EMV signature
   uint256 result = emvValidator.validateUserOp(userOp, userOpHash);
   // Returns SIG_VALIDATION_SUCCESS_UINT if valid
   ```

2. **EntryPoint calls `executeUserOp`**:
   ```solidity
   // Kernel executes the callData which calls executeEMVTransfer
   emvValidator.executeEMVTransfer(abi.encode(emvData));
   ```

3. **EMV Transfer Execution**:
   - Validates EMV data format and currency (840 USD or 997 USN)
   - Extracts amount from BCD format: `000000010000` → $100.00 → 1e18 wei
   - Executes `USDC.transferFrom(smartAccount, recipient, 1e18)`
   - Emits `EMVTransferExecuted` event

## Security Features

### Replay Protection
- **Unpredictable Number**: Each `9F37` value can only be used once per address
- **Sequential ATC**: `9F36` values must increment sequentially (0, 1, 2, ...)
- **RSA Signature**: Full PKCS#1 v1.5 SHA-256 verification

### Amount Validation
- **BCD Decoding**: Proper EMV amount format validation
- **Currency Restriction**: Only USD (840) and USN (997) allowed
- **Zero Amount Check**: Prevents zero-value transfers

## Event Tracking

The integrated validator emits comprehensive events:

```solidity
// Validation events
event EMVSignatureValidated(address indexed kernel, bool success);
event UnpredictableNumberUsed(address indexed kernel, bytes4 unpredictableNumber);
event ATCIncremented(address indexed kernel, uint16 newATC);

// Transfer events  
event EMVTransferExecuted(
    address indexed from,
    address indexed to,
    address indexed token,
    uint256 amount,
    bytes4 unpredictableNumber,
    uint16 atc
);
```

## Configuration Management

```solidity
// Update ERC20 token and recipient
emvValidator.updateExecutorConfig(newToken, newRecipient);

// Check current configuration
(address token, address recipient) = emvValidator.getExecutorConfig(account);
```

## Complete Integration Benefits

1. **Single Module**: Validation and execution in one contract
2. **Atomic Operations**: EMV validation + ERC20 transfer in one transaction
3. **Gas Efficient**: No external calls between validation and execution
4. **Secure**: All EMV security features + ERC20 transfer protection
5. **Flexible**: Configurable tokens and recipients per account

## Error Handling

The validator provides clear error messages:
- `"EMVValidator: invalid currency code"` - Only USD/USN allowed
- `"EMVValidator: unpredictable number already used"` - Replay protection
- `"EMVValidator: invalid ATC sequence"` - Sequential counter enforcement
- `"EMVValidator: token not configured"` - ERC20 setup required
- `"EMVValidator: transfer failed"` - Insufficient balance/allowance

This creates a complete bridge from EMV card transactions to on-chain ERC20 transfers with enterprise-grade security! 🚀
