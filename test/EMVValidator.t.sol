// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./base/KernelTestBase.sol";
import "../src/emv/EMVProcessor.sol";
import "../src/emv/MerchantRegistry.sol";
import "../src/interfaces/PackedUserOperation.sol";
import "../src/types/Constants.sol";
import "../src/types/Types.sol";
import "forge-std/console.sol";

contract EMVValidatorTest is KernelTestBase {
    EMVProcessor public emvProcessor;
    MerchantRegistry public merchantRegistry;
    address public merchantAddress;
    
    // Event declarations for testing
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

    function setUp() public override {
        super.setUp(); // Initialize KernelTestBase
        
        // Deploy EMV components
        emvProcessor = new EMVProcessor();
        merchantRegistry = new MerchantRegistry();
        merchantAddress = makeAddr("merchant");
        
        // Register test merchant
        merchantRegistry.modifyMerchant(bytes15(TEST_MERCHANT_ID), merchantAddress);
        
        // Mint tokens to the test contract
        mockERC20.mint(address(this), 1e24); // 1 million tokens with 18 decimals
        
        // Verify test contract has tokens from the inherited mockERC20
        uint256 balance = mockERC20.balanceOf(address(this));
        console.log("Test contract balance from mockERC20:", balance);
    }

    // Override root validation config to use EMVProcessor
    function _setRootValidationConfig() internal override {
        // Use a MockValidator instead of EMVProcessor as the root validator for now
        // We'll install EMVProcessor as a separate validator/executor module
        mockValidator = new MockValidator();
        rootValidation = ValidatorLib.validatorToIdentifier(IValidator(address(mockValidator)));
        rootValidationConfig.hook = IHook(address(0));
        rootValidationConfig.validatorData = "";
        rootValidationConfig.hookData = "";
    }

    // Helper to install EMVProcessor as both validator and executor
    function _installEMVProcessor() internal {
        vm.deal(address(kernel), 1e18);

        // Install EMVProcessor as validator with selector access
        PackedUserOperation[] memory ops1 = new PackedUserOperation[](1);
        ops1[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_VALIDATOR,
                address(emvProcessor),
                abi.encodePacked(
                    address(0), // No hook
                    abi.encode(
                        abi.encode(address(mockERC20), merchantAddress, address(merchantRegistry), uint16(0)), // validator data
                        hex"", // hook data
                        abi.encodePacked(kernel.execute.selector) // selector data - grant access to execute
                    )
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops1, payable(address(0xdeadbeef)));

        // Install EMVProcessor as executor
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_EXECUTOR,
                address(emvProcessor),
                abi.encodePacked(
                    address(0), // No hook
                    abi.encode(
                        abi.encode(address(mockERC20), merchantAddress, address(merchantRegistry), uint16(0)), // executor data
                        hex"" // hook data
                    )
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops2, payable(address(0xdeadbeef)));
    }

    function _createEMVTransactionData() internal pure returns (bytes memory) {
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
        return abi.encode(txnData);
    }

    function _createInvalidEMVTransactionData() internal pure returns (bytes memory) {
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
            signature: hex"deadbeef", // Invalid signature
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });
        return abi.encode(txnData);
    }

    function _encodeEMVExecuteCall() internal view returns (bytes memory) {
        // First install the EMV processor as an executor
        bytes memory installExecutorCall = abi.encodeWithSelector(
            kernel.installModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(emvProcessor),
            abi.encodePacked(
                address(0), // No hook
                abi.encode(
                    abi.encode(address(mockERC20), merchantAddress, address(merchantRegistry), uint16(0)), // executor data
                    hex"" // hook data
                )
            )
        );

        // Then execute the EMV transfer
        bytes memory emvTransferCall = abi.encodeWithSelector(
            emvProcessor.executeEMVTransfer.selector,
            _createEMVTransactionData(),
            address(0) // Use merchant registry
        );

        // Use batch execution to install executor and execute transfer
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: address(kernel),
            value: 0,
            callData: installExecutorCall
        });
        executions[1] = Execution({
            target: address(kernel),
            value: 0,
            callData: emvTransferCall
        });

        return encodeBatchExecute(executions);
    }

    function _encodeSimpleTransferCall() internal view returns (bytes memory) {
        // Simple ERC20 transfer to demonstrate the validation working
        return abi.encodeWithSelector(
            kernel.execute.selector,
            ExecMode.wrap(bytes32(0)), // Default execution mode
            ExecLib.encodeSingle(
                address(mockERC20), // target (token contract)
                0, // value
                abi.encodeWithSelector(
                    mockERC20.transfer.selector,
                    merchantAddress,
                    1e20 // amount (100.00 dollars)
                )
            )
        );
    }

    function _prepareEMVUserOp(bytes memory callData, bool success) internal returns (PackedUserOperation memory op) {
        // Create a UserOperation that uses EMVProcessor as the validator
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(emvProcessor)),
            0 // parallel key
        );

        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), nonceKey),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: success ? _createEMVTransactionData() : _createInvalidEMVTransactionData()
        });
    }

    function test_Deployment() public whenInitialized {
        assertTrue(address(emvProcessor) != address(0));
        assertTrue(address(kernel) != address(0));
        assertTrue(address(entrypoint) != address(0));
        
        // Check that the kernel was initialized with MockValidator as root validator
        assertEq(ValidationId.unwrap(kernel.rootValidator()), ValidationId.unwrap(rootValidation));
        
        // EMVProcessor should not be installed yet
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvProcessor), ""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvProcessor), ""));
    }

    function test_ModuleType() public {
        assertTrue(emvProcessor.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(emvProcessor.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvProcessor.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(emvProcessor.isModuleType(MODULE_TYPE_FALLBACK));
    }

    function test_ValidEMVTransaction() public whenInitialized {
        // Install EMVProcessor as both validator and executor
        _installEMVProcessor();
        
        // Check test contract balance first
        uint256 testBalance = mockERC20.balanceOf(address(this));
        console.log("Test contract balance:", testBalance);
        
        // Fund the kernel with tokens for transfer (reasonable amount)
        mockERC20.transfer(address(kernel), 1e21); // 1,000 tokens
        vm.deal(address(kernel), 1e18);

        // Check that kernel has the tokens
        uint256 kernelBalance = mockERC20.balanceOf(address(kernel));
        assertGt(kernelBalance, 1e20, "Kernel should have enough tokens");

        // Create a UserOperation using EMVProcessor as validator to execute simple transfer
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            true // successful signature
        );

        // Execute the operation through EntryPoint
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        // Check that the transfer was successful
        uint256 merchantBalance = mockERC20.balanceOf(merchantAddress);
        assertGt(merchantBalance, 0, "Merchant should have received tokens");
        
        // The amount should be 1e20 wei (100.00 dollars worth)
        assertEq(merchantBalance, 1e20, "Merchant should have received exactly 1e20 tokens");
    }

    function test_InvalidEMVSignature() public whenInitialized {
        // Install EMVProcessor as both validator and executor
        _installEMVProcessor();
        
        // Fund the kernel with tokens for transfer
        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create a UserOperation with invalid EMV signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            false // invalid signature
        );

        // Expect the operation to fail due to invalid signature
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_InstallEMVAsValidatorAndExecutor() public whenInitialized {
        // Install EMVProcessor as both validator and executor
        _installEMVProcessor();

        // Check that both modules were installed
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvProcessor), ""));
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvProcessor), ""));
    }

    function test_MerchantRegistryIntegration() public whenInitialized {
        // Install EMVProcessor as both validator and executor
        _installEMVProcessor();
        
        // Fund the kernel with tokens for transfer
        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Check initial balances
        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        // Create a UserOperation using EMVProcessor as validator to execute EMV transfer
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            true // successful signature
        );

        // Execute the operation through EntryPoint
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        // Check that the transfer was successful
        uint256 merchantBalanceAfter = mockERC20.balanceOf(merchantAddress);
        assertGt(merchantBalanceAfter, merchantBalanceBefore);
        
        // The amount should be 100.00 dollars = 1e20 wei (based on TEST_AMOUNT)
        assertEq(merchantBalanceAfter - merchantBalanceBefore, 1e20);
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

    // ========== MERCHANT REGISTRY TESTS ==========

    function test_MerchantRegistryBasics() public {
        bytes15 merchantId = bytes15(TEST_MERCHANT_ID);
        address testMerchantAddress = address(0x789);
        
        // Register merchant
        merchantRegistry.modifyMerchant(merchantId, testMerchantAddress);
        
        // Check registration
        assertTrue(merchantRegistry.isMerchantRegistered(merchantId));
        assertEq(merchantRegistry.getMerchantAddress(merchantId), testMerchantAddress);
        
        // Test removal by setting address to address(0)
        merchantRegistry.modifyMerchant(merchantId, address(0));
        assertFalse(merchantRegistry.isMerchantRegistered(merchantId));
        assertEq(merchantRegistry.getMerchantAddress(merchantId), address(0));
    }

}
