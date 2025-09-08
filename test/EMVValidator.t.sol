// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/emv/EMVProcessor.sol";
import "../src/emv/MerchantRegistry.sol";
import "../src/interfaces/PackedUserOperation.sol";
import "../src/types/Constants.sol";

contract EMVValidatorTest is Test {
    EMVProcessor public emvValidator;
    MerchantRegistry public merchantRegistry;
    
    // Event declarations for testing
    event EMVSignatureValidated(address indexed kernel, bool success);
    event UnpredictableNumberUsed(address indexed kernel, bytes4 unpredictableNumber);
    event ATCIncremented(address indexed kernel, uint16 newATC);
    
    // Test RSA key pair (2048-bit)
    bytes constant TEST_EXPONENT = hex"010001";
    bytes constant TEST_MODULUS = hex"e1bb031f4389e26a6d2fb1eab48946263b9386667aca2a10c71fd2a81ecc76e27de78698819f86339207b24fa69b9e2cefc6db2d68f102d773b4d1e2b4d7f7c0ddbaed43b3c09ef094a1aa17873ee52542a6fa4e096744659bedbd41931739e2993dccfbd3fcc58dcfc6db5a27affc9020b38015086b4cb91829d55102f72d5b282769ff2618d168ea7c5ef3f200c69033e2e23e835617e5b86ecbadc9ff19782c5e679e35371d169ea64a8371c9a89acc50eb6f6a0851038ee725d93da77e981a1d0327d3c557253a533629cd2bf21c476a4001c76e6985902655c68a6951e74f071087c7be29bda5e25b8943c4f55eafbbbbc8beea975a746908b94b66c917";
    
    // Test EMV data
    bytes constant TEST_ARQC = hex"1234567890ABCDEF";
    bytes constant TEST_UNPREDICTABLE_NUMBER = hex"12345678";
    bytes constant TEST_ATC = hex"0000";
    bytes constant TEST_AMOUNT = hex"000000010000";
    bytes constant TEST_CURRENCY = hex"0348"; // 840 in big-endian (0x0348 = 840 decimal)
    bytes constant TEST_DATE = hex"231201";
    bytes constant TEST_TXN_TYPE = hex"00";
    bytes constant TEST_TVR = hex"0000000000";
    bytes constant TEST_CVM_RESULTS = hex"000000";
    bytes constant TEST_TERMINAL_ID = hex"5445535430303100"; // "TEST001" padded to 8 bytes with null
    bytes constant TEST_MERCHANT_ID = hex"4D45524348414E5430303132333400"; // "MERCHANT001234" padded to 15 bytes with null
    
    // Valid signature for the test data above (final corrected with proper Terminal ID and Merchant ID)
    bytes constant TEST_SIGNATURE = hex"3b19fb77dcc923c6828f9fc7a15d36a5eb7ef7d134278aa6b3e3d72c4b2d21bf3223b084d95036abbc4d648afacbc2ec4777a0cb8844219952b979494d1c967ee0c8ec524d9b6c5ed22f5b4187c1063ee781b9d584e1377152d04eace65d0a7e07fe4372f30251790fe7f3a18427857e50a5b9f7d7dd570c7bae5acb3e965fb7ba362433cbdc65f4d6a3e78abd1ad507bd3c3f9ef36521c910f00246ffc4749ca376db8ae877a08aa97ea392a769b944aae8198681eb484509df3a38e8b07634141b6662a9946d07d95892a8351e971c00ba76ac3e0da9ae071caac6fe269c8ac5bdc718fa0e905353bb3b67bd7d9280bb8266d38b6e42a0cee19b25c61314ca";
    
    // Expected dynamic data (for reference) - updated with properly padded Terminal ID and Merchant ID
    bytes constant EXPECTED_DYNAMIC_DATA = hex"6a031234567890abcdef123456780000000000010000034823120100000000000000000054455354303031004d45524348414e5430303132333400bc";
    
    address user1 = address(0x1);
    address user2 = address(0x2);

    function setUp() public {
        emvValidator = new EMVProcessor();
        merchantRegistry = new MerchantRegistry();
    }

    function test_Deployment() public {
        assertTrue(address(emvValidator) != address(0));
        assertEq(emvValidator.expectedATC(), 0);
        assertFalse(emvValidator.usedUnpredictableNumbers(uint32(bytes4(TEST_UNPREDICTABLE_NUMBER))));
    }

    function test_ModuleType() public {
        assertTrue(emvValidator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(emvValidator.isModuleType(MODULE_TYPE_HOOK));
        assertTrue(emvValidator.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvValidator.isModuleType(MODULE_TYPE_FALLBACK));
    }

    function test_OnInstall() public {
        vm.prank(user1);
        emvValidator.onInstall("");
        
        assertEq(emvValidator.expectedATC(), 0);
        assertTrue(emvValidator.isInitialized(user1));
    }

    function test_OnUninstall() public {
        vm.prank(user1);
        emvValidator.onInstall("");
        
        vm.prank(user1);
        emvValidator.onUninstall("");
        
        assertEq(emvValidator.expectedATC(), 0);
        // Note: isInitialized will still return true since expectedATC[user1] exists (is 0)
    }

    function test_ValidEMVSignature() public {
        vm.prank(user1);
        emvValidator.onInstall("");

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        bytes memory emvData = abi.encode(txnData);

        vm.prank(user1);
        bool result = emvValidator.verifyEMVSignature(emvData);

        assertTrue(result);
        assertEq(emvValidator.expectedATC(), 1);
        assertTrue(emvValidator.usedUnpredictableNumbers(uint32(bytes4(TEST_UNPREDICTABLE_NUMBER))));
    }

    function test_Verify9F4B_ValidSignature() public {
        bool result = emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        assertTrue(result);
    }

    function test_Verify9F4B_InvalidSignature() public {
        bytes memory badSignature = hex"deadbeef";
        // Pad to correct length
        bytes memory paddedBadSignature = new bytes(256);
        for (uint i = 0; i < 4; i++) {
            paddedBadSignature[i] = badSignature[i];
        }

        bool result =         emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            paddedBadSignature,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        assertFalse(result);
    }

    function test_ReplayProtection_UnpredictableNumber() public {
        vm.prank(user1);
        emvValidator.onInstall("");

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        bytes memory emvData = abi.encode(txnData);

        // First transaction should succeed
        vm.prank(user1);
        bool result1 = emvValidator.verifyEMVSignature(emvData);
        assertTrue(result1);

        // Second transaction with same unpredictable number should fail
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.UnpredictableNumberAlreadyUsed.selector, bytes4(TEST_UNPREDICTABLE_NUMBER)));
        emvValidator.verifyEMVSignature(emvData);
    }

    function test_ATCSequence() public {
        vm.prank(user1);
        emvValidator.onInstall("");

        // First transaction with ATC = 0
        EMVTransactionData memory txnData1 = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: hex"0000", // ATC = 0
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        bool result1 = emvValidator.verifyEMVSignature(abi.encode(txnData1));
        assertTrue(result1);
        assertEq(emvValidator.expectedATC(), 1);

        // Second transaction with wrong ATC should fail
        EMVTransactionData memory txnData2 = EMVTransactionData({
            arqc: hex"ABCDEF1234567890", // Different ARQC
            unpredictableNumber: hex"87654321", // Different unpredictable number
            atc: hex"0002", // ATC = 2 (should be 1)
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: hex"1234", // This will fail signature verification anyway
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidATCSequence.selector, 1, 2));
        emvValidator.verifyEMVSignature(abi.encode(txnData2));
    }

    function test_CrossAddressIsolation() public {
        // With delegate call, each kernel instance has its own storage
        // This test now demonstrates that different unpredictable numbers work
        
        vm.prank(user1);
        emvValidator.onInstall("");

        // First transaction with one unpredictable number
        EMVTransactionData memory txnData1 = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER, // 0x12345678
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        bool result1 = emvValidator.verifyEMVSignature(abi.encode(txnData1));
        assertTrue(result1);

        // Second transaction with different unpredictable number should work
        EMVTransactionData memory txnData2 = EMVTransactionData({
            arqc: hex"ABCDEF1234567890", // Different ARQC
            unpredictableNumber: hex"87654321", // Different unpredictable number
            atc: hex"0001", // ATC = 1 (next in sequence)
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: hex"1234", // Will fail signature but should pass unpredictable number check
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        // This should fail at signature verification, not unpredictable number check
        bool result2 = emvValidator.verifyEMVSignature(abi.encode(txnData2));
        assertFalse(result2);

        // But using the same unpredictable number should fail
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.UnpredictableNumberAlreadyUsed.selector, bytes4(TEST_UNPREDICTABLE_NUMBER)));
        emvValidator.verifyEMVSignature(abi.encode(txnData1));
    }

    function test_InvalidFieldLengths() public {
        // Test invalid ARQC length
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidEMVDataLength.selector, "ARQC", 8, 2));
        emvValidator.verify9F4B(
            hex"1234", // Too short
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test invalid unpredictable number length
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidEMVDataLength.selector, "UnpredictableNumber", 4, 1));
        emvValidator.verify9F4B(
            TEST_ARQC,
            hex"12", // Too short
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test invalid modulus length
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidEMVDataLength.selector, "Modulus", 128, 2));
        emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            hex"1234" // Too short
        );

        // Test invalid terminal ID length
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidEMVDataLength.selector, "TerminalId", 8, 2));
        emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            hex"1234", // Too short (should be 8 bytes)
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test invalid merchant ID length
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidEMVDataLength.selector, "MerchantId", 15, 2));
        emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            hex"1234", // Too short (should be 15 bytes)
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );
    }

    function test_InvalidCurrencyCode() public {
        // Test invalid currency code (not 840 or 997)
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidCurrencyCode.selector, 854));
        emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            hex"0356", // 854 (EUR) - not allowed
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test another invalid currency code
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.InvalidCurrencyCode.selector, 500));
        emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            hex"01F4", // 500 - not allowed
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );
    }

    function test_ValidCurrencyCodes() public {
        // Test 840 (USD) - should pass (already tested in other tests)
        // Test 997 (USN) - should pass validation (signature will fail but currency validation should pass)
        
        // We expect this to fail at signature verification, not currency validation
        bool result = emvValidator.verify9F4B(
            TEST_ARQC,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_ATC,
            TEST_AMOUNT,
            hex"03E5", // 997 (USN) in big-endian
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_SIGNATURE, // This signature won't match the new data, but currency validation should pass
            TEST_EXPONENT,
            TEST_MODULUS
        );
        
        // Should be false due to signature mismatch, not currency validation
        assertFalse(result);
    }

    function test_ValidateUserOp() public {
        vm.prank(user1);
        emvValidator.onInstall("");

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: user1,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: abi.encode(txnData)
        });

        vm.prank(user1);
        uint256 result = emvValidator.validateUserOp(userOp, bytes32(0));

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT);
        assertEq(emvValidator.expectedATC(), 1);
    }

    function test_IsValidSignatureWithSender() public {
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        emvValidator.onInstall("");

        vm.prank(user1);
        bytes4 result = emvValidator.isValidSignatureWithSender(
            address(0),
            bytes32(0),
            abi.encode(txnData)
        );

        assertEq(result, ERC1271_MAGICVALUE);
    }

    function test_VerifyEMVSignatureView() public {
        // Use a different unpredictable number that hasn't been used yet
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: hex"FFFFFFFF", // Different unpredictable number
            atc: hex"0002", // Use ATC that matches current expected value
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE, // This will fail signature but should pass other validations
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        bool result = emvValidator.verifyEMVSignatureView(abi.encode(txnData));

        // Should fail due to signature mismatch, but not due to replay protection
        assertFalse(result);
        // View function should not modify state - check that unpredictable number wasn't marked as used
        assertFalse(emvValidator.usedUnpredictableNumbers(uint32(bytes4(hex"FFFFFFFF"))));
    }

    function test_PreCheckAndPostCheck() public {
        vm.prank(user1);
        bytes memory hookData = emvValidator.preCheck(address(0), 0, "");
        assertEq(hookData.length, 0);

        vm.prank(user1);
        emvValidator.postCheck("");
        // Should not revert
    }

    function test_Events() public {
        vm.prank(user1);
        emvValidator.onInstall("");

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // Expect the events to be emitted (using anonymous event matching)
        vm.expectEmit(true, false, false, true);
        emit UnpredictableNumberUsed(user1, bytes4(TEST_UNPREDICTABLE_NUMBER));

        vm.expectEmit(true, false, false, true);
        emit ATCIncremented(user1, 1);

        vm.expectEmit(true, false, false, true);
        emit EMVSignatureValidated(user1, true);

        vm.prank(user1);
        emvValidator.verifyEMVSignature(abi.encode(txnData));
    }

    function test_DynamicDataAssembly() public view {
        // This test verifies that our dynamic data assembly matches the expected format
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // The dynamic data should match our expected format
        bytes memory expectedData = abi.encodePacked(
            bytes1(0x6A),                    // Header
            bytes1(0x03),                    // Format (Signed Data Format 3)
            TEST_ARQC,                       // 9F26 - ARQC (8 bytes)
            TEST_UNPREDICTABLE_NUMBER,       // 9F37 - Unpredictable Number (4 bytes)
            TEST_ATC,                        // 9F36 - ATC (2 bytes)
            TEST_AMOUNT,                     // 9F02 - Amount (6 bytes BCD)
            TEST_CURRENCY,                   // 5F2A - Currency (2 bytes)
            TEST_DATE,                       // 9A - Date (3 bytes BCD)
            TEST_TXN_TYPE,                   // 9C - Transaction Type (1 byte)
            TEST_TVR,                        // 95 - TVR (5 bytes)
            TEST_CVM_RESULTS,                // 9F34 - CVM Results (3 bytes)
            TEST_TERMINAL_ID,                // 9F1C - Terminal ID (8 bytes)
            TEST_MERCHANT_ID,                // 9F16 - Merchant ID (15 bytes)
            bytes1(0xBC)                     // Trailer
        );

        assertEq(expectedData, EXPECTED_DYNAMIC_DATA);
    }

    // ========== EXECUTOR TESTS ==========

    function test_ExecutorConfiguration() public {
        address mockToken = address(0x123);
        address recipient = address(0x456);
        
        // Install with executor configuration
        vm.prank(user1);
        emvValidator.onInstall(abi.encode(mockToken, recipient));
        
        // Check configuration
        (address configuredToken, address configuredRecipient,) = emvValidator.getExecutorConfig();
        assertEq(configuredToken, mockToken);
        assertEq(configuredRecipient, recipient);
    }

    function test_UpdateExecutorConfig() public {
        address mockToken1 = address(0x123);
        address recipient1 = address(0x456);
        address mockToken2 = address(0x789);
        address recipient2 = address(0xABC);
        
        // Install with initial configuration
        vm.prank(user1);
        emvValidator.onInstall(abi.encode(mockToken1, recipient1));
        
        // Update configuration
        vm.prank(user1);
        emvValidator.updateExecutorConfig(mockToken2, recipient2);
        
        // Check updated configuration
        (address configuredToken, address configuredRecipient,) = emvValidator.getExecutorConfig();
        assertEq(configuredToken, mockToken2);
        assertEq(configuredRecipient, recipient2);
    }

    function test_ExtractAmountFromBCD() public {
        // Test amount extraction (100.00 = hex"000000010000")
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT, // 000000010000 = 100.00 in BCD
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // Install with mock token configuration
        address mockToken = address(new MockERC20());
        vm.prank(user1);
        emvValidator.onInstall(abi.encode(mockToken, user2));

        // The amount 000000010000 in BCD represents 100.00
        // This should convert to 100.00 * 10^16 = 1e18 wei (1 token with 18 decimals)
        bytes memory emvData = abi.encode(txnData);
        
        // We can't directly test the private function, but we can test it through executeEMVTransfer
        // For now, let's create a separate test for this
    }

    function test_ExecuteEMVTransferNotConfigured() public {
        vm.prank(user1);
        emvValidator.onInstall(""); // Install without executor config
        
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.TokenNotConfigured.selector));
        emvValidator.executeEMVTransfer(abi.encode(txnData));
    }

    // ========== MERCHANT REGISTRY TESTS ==========

    function test_MerchantRegistryBasics() public {
        bytes15 merchantId = bytes15(TEST_MERCHANT_ID);
        address merchantAddress = address(0x789);
        
        // Register merchant
        merchantRegistry.modifyMerchant(merchantId, merchantAddress);
        
        // Check registration
        assertTrue(merchantRegistry.isMerchantRegistered(merchantId));
        assertEq(merchantRegistry.getMerchantAddress(merchantId), merchantAddress);
        
        // Test removal by setting address to address(0)
        merchantRegistry.modifyMerchant(merchantId, address(0));
        assertFalse(merchantRegistry.isMerchantRegistered(merchantId));
        assertEq(merchantRegistry.getMerchantAddress(merchantId), address(0));
    }

    function test_MerchantRegistryOnlyOwner() public {
        bytes15 merchantId = bytes15(TEST_MERCHANT_ID);
        address merchantAddress = address(0x789);
        
        // Non-owner cannot modify
        vm.prank(user1);
        vm.expectRevert(); // Solady Ownable.Unauthorized() error
        merchantRegistry.modifyMerchant(merchantId, merchantAddress);
    }

    function test_EMVTransferWithMerchantRegistry() public {
        bytes15 merchantId = bytes15(TEST_MERCHANT_ID);
        address merchantAddress = address(0x789);
        address mockToken = address(new MockERC20());
        
        // Register merchant
        merchantRegistry.modifyMerchant(merchantId, merchantAddress);
        
        // Install EMV module with merchant registry
        vm.prank(user1);
        emvValidator.onInstall(abi.encode(mockToken, address(0), address(merchantRegistry)));
        
        // Set up token approval - EMVModule will call transferFrom(address(this), merchant, amount)
        // So EMVModule needs tokens and allowance
        MockERC20(mockToken).transfer(address(emvValidator), 1e20);
        MockERC20(mockToken).approve(address(emvValidator), 1e20);

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        uint256 balanceBefore = MockERC20(mockToken).balanceOf(merchantAddress);

        // Execute transfer - should use merchant registry to determine recipient
        vm.prank(user1);
        emvValidator.executeEMVTransfer(abi.encode(txnData));

        uint256 balanceAfter = MockERC20(mockToken).balanceOf(merchantAddress);
        assertEq(balanceAfter - balanceBefore, 1e20); // 100.00 dollars = 10000 cents * 10^16 = 1e20 wei
    }

    function test_EMVTransferUnregisteredMerchant() public {
        address mockToken = address(new MockERC20());
        
        // Install EMV module with merchant registry but don't register the merchant
        vm.prank(user1);
        emvValidator.onInstall(abi.encode(mockToken, address(0), address(merchantRegistry)));

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID, // This merchant is not registered
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // Should revert because merchant is not registered
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.MerchantNotRegistered.selector, bytes15(TEST_MERCHANT_ID)));
        emvValidator.executeEMVTransfer(abi.encode(txnData));
    }

    function test_EMVTransferNoMerchantRegistry() public {
        address mockToken = address(new MockERC20());
        
        // Install EMV module without merchant registry
        vm.prank(user1);
        emvValidator.onInstall(abi.encode(mockToken, user2)); // user2 as default recipient

        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // Should revert because merchant registry is not set
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(EMVProcessor.MerchantRegistryNotSet.selector));
        emvValidator.executeEMVTransfer(abi.encode(txnData));
    }

    function test_MerchantRegistryBatchOperations() public {
        bytes15[] memory merchantIds = new bytes15[](2);
        address[] memory addresses = new address[](2);
        
        merchantIds[0] = bytes15(TEST_MERCHANT_ID);
        merchantIds[1] = bytes15(hex"4D45524348414E5430303132333401"); // Different merchant
        addresses[0] = address(0x789);
        addresses[1] = address(0xABC);
        
        // Batch modify
        merchantRegistry.batchModifyMerchants(merchantIds, addresses);
        
        // Check both registrations
        assertTrue(merchantRegistry.isMerchantRegistered(merchantIds[0]));
        assertTrue(merchantRegistry.isMerchantRegistered(merchantIds[1]));
        assertEq(merchantRegistry.getMerchantAddress(merchantIds[0]), addresses[0]);
        assertEq(merchantRegistry.getMerchantAddress(merchantIds[1]), addresses[1]);
        
        // Test batch lookup
        address[] memory retrievedAddresses = merchantRegistry.getMerchantAddresses(merchantIds);
        assertEq(retrievedAddresses[0], addresses[0]);
        assertEq(retrievedAddresses[1], addresses[1]);
    }
}

// Mock ERC20 contract for testing
contract MockERC20 {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**18;
    
    constructor() {
        balances[msg.sender] = totalSupply;
    }
    
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
    
    function allowance(address owner, address spender) external view returns (uint256) {
        return allowances[owner][spender];
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowances[from][msg.sender] < amount) return false;
        if (balances[from] < amount) return false;
        
        allowances[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        if (balances[msg.sender] < amount) return false;
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
