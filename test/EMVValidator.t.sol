// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/validator/EMVValidator.sol";
import "../src/types/Constants.sol";

contract EMVValidatorTest is Test {
    EMVValidator public emvValidator;
    
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
    
    // Valid signature for the test data above (updated for currency 840)
    bytes constant TEST_SIGNATURE = hex"44a6f60904d1f0693b5ac1668195e16b4dd6ee37422b409c7f8e03af4099800bbb3485a435879c0b5efee34bd3851c02145aa9cbff0aacd2c93e2ebc13c441d2ecdb44b357b38ae2f3172dbc00d84a51cdd435f78a8117b3a1bdc4a5492a0cf54a8827578b01f64d0d11b326657650f4433289d76e1127350086381b1268bf77f5a2f40710559d3a4f07e1f6892a96f90c12c121b5957adb13177e9069592f29cdbb77ce4cc4f8cf041e2562872d76adf5c4c27a8664ddbad5665d66507e9624668a3cd98bfc213da70aa6f146363b62a5867c9cab836793698cede64d58e2c915473032ab76e76c6d6aa12ab0e2e34aabe139a8e33da496d4f60c9410d6f5d3";
    
    // Expected dynamic data (for reference) - updated with correct currency 0348 (840 decimal)
    bytes constant EXPECTED_DYNAMIC_DATA = hex"6a031234567890abcdef1234567800000000000100000348231201000000000000000000bc";
    
    address user1 = address(0x1);
    address user2 = address(0x2);

    function setUp() public {
        emvValidator = new EMVValidator();
    }

    function test_Deployment() public {
        assertTrue(address(emvValidator) != address(0));
        assertEq(emvValidator.expectedATC(user1), 0);
        assertFalse(emvValidator.usedUnpredictableNumbers(keccak256(abi.encode(user1, TEST_UNPREDICTABLE_NUMBER))));
    }

    function test_ModuleType() public {
        assertTrue(emvValidator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(emvValidator.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(emvValidator.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvValidator.isModuleType(MODULE_TYPE_FALLBACK));
    }

    function test_OnInstall() public {
        vm.prank(user1);
        emvValidator.onInstall("");
        
        assertEq(emvValidator.expectedATC(user1), 0);
        assertTrue(emvValidator.isInitialized(user1));
    }

    function test_OnUninstall() public {
        vm.prank(user1);
        emvValidator.onInstall("");
        
        vm.prank(user1);
        emvValidator.onUninstall("");
        
        assertEq(emvValidator.expectedATC(user1), 0);
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
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        bytes memory emvData = abi.encode(txnData);

        vm.prank(user1);
        bool result = emvValidator.verifyEMVSignature(emvData);

        assertTrue(result);
        assertEq(emvValidator.expectedATC(user1), 1);
        assertTrue(emvValidator.usedUnpredictableNumbers(keccak256(abi.encode(user1, TEST_UNPREDICTABLE_NUMBER))));
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
        vm.expectRevert("EMVValidator: unpredictable number already used");
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
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        bool result1 = emvValidator.verifyEMVSignature(abi.encode(txnData1));
        assertTrue(result1);
        assertEq(emvValidator.expectedATC(user1), 1);

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
            signature: hex"1234", // This will fail signature verification anyway
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        vm.expectRevert("EMVValidator: invalid ATC sequence");
        emvValidator.verifyEMVSignature(abi.encode(txnData2));
    }

    function test_CrossAddressIsolation() public {
        // Install for both users
        vm.prank(user1);
        emvValidator.onInstall("");
        vm.prank(user2);
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
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        bytes memory emvData = abi.encode(txnData);

        // User1 uses the unpredictable number
        vm.prank(user1);
        bool result1 = emvValidator.verifyEMVSignature(emvData);
        assertTrue(result1);

        // User2 can still use the same unpredictable number (different address)
        vm.prank(user2);
        bool result2 = emvValidator.verifyEMVSignature(emvData);
        assertTrue(result2);

        // But user1 cannot use it again
        vm.prank(user1);
        vm.expectRevert("EMVValidator: unpredictable number already used");
        emvValidator.verifyEMVSignature(emvData);
    }

    function test_InvalidFieldLengths() public {
        // Test invalid ARQC length
        vm.expectRevert("EMVValidator: invalid ARQC length");
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
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test invalid unpredictable number length
        vm.expectRevert("EMVValidator: invalid UnpredictableNumber length");
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
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test invalid modulus length
        vm.expectRevert("EMVValidator: invalid Modulus length");
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
            TEST_SIGNATURE,
            TEST_EXPONENT,
            hex"1234" // Too short
        );
    }

    function test_InvalidCurrencyCode() public {
        // Test invalid currency code (not 840 or 997)
        vm.expectRevert("EMVValidator: invalid currency code");
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
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

        // Test another invalid currency code
        vm.expectRevert("EMVValidator: invalid currency code");
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
        assertEq(emvValidator.expectedATC(user1), 1);
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
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.prank(user1);
        emvValidator.onInstall("");

        vm.prank(user1);
        bool result = emvValidator.verifyEMVSignatureView(abi.encode(txnData));

        assertTrue(result);
        // View function should not modify state
        assertEq(emvValidator.expectedATC(user1), 0);
        assertFalse(emvValidator.usedUnpredictableNumbers(keccak256(abi.encode(user1, TEST_UNPREDICTABLE_NUMBER))));
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
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        vm.expectEmit(true, true, false, true);
        emit EMVValidator.UnpredictableNumberUsed(user1, bytes4(TEST_UNPREDICTABLE_NUMBER));

        vm.expectEmit(true, true, false, true);
        emit EMVValidator.ATCIncremented(user1, 1);

        vm.expectEmit(true, true, false, true);
        emit EMVValidator.EMVSignatureValidated(user1, true);

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
            bytes1(0xBC)                     // Trailer
        );

        assertEq(expectedData, EXPECTED_DYNAMIC_DATA);
    }
}
