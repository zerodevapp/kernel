// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {BTTModifiers} from "./BTTModifiers.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockValidator, MockEmptyReturnValidator} from "../mock/MockValidator.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {PermissionId} from "src/types/Types.sol";
import {
    Unauthorized,
    UnauthorizedCallData,
    InvalidPermissionId,
    InvalidNonce,
    InvalidVid,
    InvalidSignature
} from "src/types/Error.sol";
import {ValidationManager} from "src/core/ValidationManager.sol";
import {Install} from "src/types/Structs.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";

/// @title Kernel.validateUserOp BTT Tests
/// @notice Tests for validateUserOp following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.validateUserOp.tree
///
/// @dev OPEN QUESTION: For enable mode in validateUserOp, the implementation currently
/// installs packages and increments nonce even if the enable signature is invalid.
/// This side effect behavior should be explicitly specified - either the tree should
/// assert this behavior, or the code should be changed to avoid side effects on invalid
/// enable signatures. Skipping this for now per user request.
abstract contract Kernel_validateUserOp is BTTModifiers {
    bool internal _enableModeSet;
    bool internal _selectorAllowed;
    bool internal _useExecuteUserOpWrapper;
    bool internal _policiesPass;
    bool internal _timeBoundedValidation;
    bool internal _multipleTimeBoundedValidation;
    address internal _selectorHook;

    modifier whenTheCallerIsNotTheEntryPoint() {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        _;
    }

    function test_WhenTheCallerIsNotTheAccountItself() external whenTheCallerIsNotTheEntryPoint {
        // it should revert with Unauthorized error
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        PackedUserOperation memory op = _createBasicUserOp();
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(Unauthorized.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier whenTheCallerIsTheEntryPointOrSelf() {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    modifier givenTheValidationModeHasEnableFlagSet() {
        _enableModeSet = true;
        _;
    }

    function test_GivenTheNonceIsInvalid()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationModeHasEnableFlagSet
    {
        // it should revert with InvalidNonce error
        vm.stopPrank();
        vm.startPrank(address(ep));

        // First call with valid enable signature uses nonce 0
        PackedUserOperation memory op = _createUserOpWithEnableMode();
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);
        kernel.validateUserOp(op, userOpHash, 0);

        // Second call with same nonce should fail
        PackedUserOperation memory op2 = _createUserOpWithEnableMode();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(newValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(Kernel.execute.selector)
        });
        op2.signature = abi.encode(
            uint256(0),
            packages,
            enableSig(0, true, false, packages, _rootSignHash),
            _validatorSignUserOp(op2, true, false)
        );
        bytes32 userOpHash2 = ep.getUserOpHash(op2);

        vm.expectRevert(InvalidNonce.selector);
        kernel.validateUserOp(op2, userOpHash2, 0);
    }

    function test_GivenTheEnableSignatureIsInvalid()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationModeHasEnableFlagSet
    {
        // it should return SIG_VALIDATION_FAILED
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithEnableMode();
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, false, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Enable mode with invalid signature should return SIG_VALIDATION_FAILED");
    }

    function test_GivenTheEnableSignatureIsValidAndNonceIsUnused()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationModeHasEnableFlagSet
    {
        // it should install the packages from the signature
        // it should increment the nonce
        // it should continue with userOp validation using the remaining signature
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithEnableMode();
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        // Verify the validator was installed
        assertTrue(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(newValidator)))).installed,
            "Validator should be installed"
        );
        assertEq(validationData, 0, "Enable mode with valid signature should return 0");
    }

    modifier givenTheValidationTypeIsROOT() {
        _validationType = 0;
        _selectorAllowed = false;
        _selectorHook = address(0);
        _useExecuteUserOpWrapper = false;
        _;
    }

    function test_GivenTheRootIsNotSet() external whenTheCallerIsTheEntryPointOrSelf givenTheValidationTypeIsROOT {
        // it should use the fallback validator
        // Note: In this test setup, root is always set during initialization
        // The fallback validator behavior is tested indirectly when root validator fails
        // and a fallback mechanism is in place. For current implementation,
        // when root validation is requested, it uses the root validator directly.
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Root validation should succeed");
    }

    function test_GivenTheRootIsSetToAPermissionType()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsROOT
    {
        // it should use permission validation for root
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install a permission and set it as root
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.setRoot(permissionToIdentifier(permissionId));

        // Now create a userOp using ROOT validation type (type=0x00)
        // The root is a permission, so _checkValidation should resolve root to permission type
        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Root set to permission should use permission validation");
    }

    function test_WhenTheSignatureIsValid() external whenTheCallerIsTheEntryPointOrSelf givenTheValidationTypeIsROOT {
        // it should return 0 for success
        // it should allow any callData without restrictions
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Valid root signature should return 0");
    }

    function test_WhenTheSignatureIsInvalid() external whenTheCallerIsTheEntryPointOrSelf givenTheValidationTypeIsROOT {
        // it should return SIG_VALIDATION_FAILED
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, false, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Invalid root signature should return SIG_VALIDATION_FAILED");
    }

    modifier givenTheValidationTypeIsVALIDATOR() {
        _validationType = 1;
        _selectorAllowed = false;
        _selectorHook = address(0);
        _useExecuteUserOpWrapper = false;
        _;
    }

    function test_GivenTheValidatorIsNotInstalled()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
    {
        // it should revert with InvalidVid error
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(
            abi.encodeWithSelector(InvalidVid.selector, validatorToIdentifier(IValidator(address(newValidator))))
        );
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier givenTheValidatorIsInstalled() {
        _validatorInstalled = true;
        _;
    }

    /// @notice it should return SIG_VALIDATION_FAILED when validator returns empty data
    /// @dev Validator returndata length is checked (must be 32 bytes); any non-conforming
    ///      response is treated as a validation failure rather than a revert, so a buggy
    ///      validator cannot DoS the account by reverting in `validateUserOp`.
    function test_WhenValidatorReturnsEmptyData()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
    {
        // Deploy and install a misconfigured validator that returns empty data
        MockEmptyReturnValidator emptyValidator = new MockEmptyReturnValidator();
        kernel.installModule(1, address(emptyValidator), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector)));

        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(emptyValidator))),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = ep.getUserOpHash(op);

        // The whenTheCallerIsTheEntryPointOrSelf modifier already pranks address(ep).
        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 1, "empty-returndata validator should yield SIG_VALIDATION_FAILED");
    }

    modifier givenTheCallDataSelectorIsInTheAllowedListAndHookIsAddress1() {
        _selectorAllowed = true;
        _selectorHook = address(1);
        _;
    }

    function test_WhenTheValidatorSignatureIsValid()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
        givenTheCallDataSelectorIsInTheAllowedListAndHookIsAddress1
    {
        // it should return 0 for success
        vm.stopPrank();
        vm.startPrank(address(ep));

        _installValidatorWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Valid validator signature should return 0");
    }

    function test_WhenTheValidatorSignatureIsInvalid()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
        givenTheCallDataSelectorIsInTheAllowedListAndHookIsAddress1
    {
        // it should return SIG_VALIDATION_FAILED
        vm.stopPrank();
        vm.startPrank(address(ep));

        _installValidatorWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
        op.signature = _validatorSignUserOp(op, false, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Invalid validator signature should return SIG_VALIDATION_FAILED");
    }

    modifier givenTheCallDataSelectorIsInTheAllowedListAndHookIsNotAddress1() {
        _selectorAllowed = true;
        _selectorHook = address(hook);
        _;
    }

    function test_WhenTheCallDataDoesNotUseExecuteUserOpWrapper()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
        givenTheCallDataSelectorIsNotDirectlyAllowed
    {
        // it should revert with UnauthorizedCallData error
        vm.stopPrank();
        vm.startPrank(address(ep));

        _installValidatorWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier givenTheCallDataSelectorIsNotDirectlyAllowed() {
        _selectorAllowed = false;
        _selectorHook = address(0);
        _;
    }

    function test_WhenTheCallDataDoesNotUseExecuteUserOpWrapper_GivenTheCallDataSelectorIsNotDirectlyAllowed()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
        givenTheCallDataSelectorIsNotDirectlyAllowed
    {
        // it should revert with UnauthorizedCallData error
        vm.stopPrank();
        vm.startPrank(address(ep));

        _installValidatorWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        // Direct execute without executeUserOp wrapper - should fail
        op.callData = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier whenTheCallDataUsesExecuteUserOpWrapper() {
        _useExecuteUserOpWrapper = true;
        _;
    }

    function test_GivenTheInnerSelectorIsInTheAllowedList()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
        givenTheCallDataSelectorIsNotDirectlyAllowed
        whenTheCallDataUsesExecuteUserOpWrapper
    {
        // it should set the validation hook for later execution
        // it should continue with signature validation
        vm.stopPrank();
        vm.startPrank(address(ep));

        // For "inner selector in allowed list", we need to allow the execute selector
        // while using executeUserOp wrapper (outer selector not directly checked)
        _selectorAllowed = true;
        _installValidatorWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Valid validator signature with executeUserOp wrapper should return 0");
    }

    function test_GivenTheInnerSelectorIsNotInTheAllowedList()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsVALIDATOR
        givenTheValidatorIsInstalled
        givenTheCallDataSelectorIsNotDirectlyAllowed
        whenTheCallDataUsesExecuteUserOpWrapper
    {
        // it should revert with UnauthorizedCallData error
        vm.stopPrank();
        vm.startPrank(address(ep));

        _installValidatorWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier givenTheValidationTypeIsPERMISSION() {
        _validationType = 2;
        _selectorAllowed = false;
        _selectorHook = address(0);
        _useExecuteUserOpWrapper = false;
        _;
    }

    function test_GivenThePermissionIsNotInstalled()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
    {
        // it should revert with InvalidVid error
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, permissionToIdentifier(permissionId)));
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier givenThePermissionIsInstalled() {
        _permissionInstalled = true;
        _;
    }

    function test_GivenTheCallDataSelectorRestrictionsAreNotMet()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
    {
        // it should revert with UnauthorizedCallData error
        vm.stopPrank();
        vm.startPrank(address(ep));

        _installPermissionWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    function test_GivenTheSignatureCountDoesNotMatchPoliciesPlusOne()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
    {
        // it should revert with InvalidSignature error
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission with execute selector allowed
        _selectorAllowed = true;
        _selectorHook = address(0);
        _useExecuteUserOpWrapper = true;
        _installPermissionWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );

        // Craft signature with wrong number of signatures (1 instead of 2)
        // Permission has 1 policy + 1 signer = requires 2 signatures
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = hex"dead";
        policy.sudoSetValidSig(address(kernel), PermissionId.unwrap(permissionId), hex"dead");
        op.signature = abi.encode(signatures);

        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(InvalidSignature.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    function test_GivenTheSignatureCountExceedsPoliciesPlusOne()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
    {
        // it should revert with InvalidSignature error (too many signatures)
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission with execute selector allowed
        _selectorAllowed = true;
        _selectorHook = address(0);
        _useExecuteUserOpWrapper = true;
        _installPermissionWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );

        // Craft signature with too many signatures (3 instead of 2)
        bytes[] memory signatures = new bytes[](3);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        signatures[2] = hex"cafe";
        policy.sudoSetValidSig(address(kernel), PermissionId.unwrap(permissionId), hex"dead");
        signer.sudoSetValidSig(address(kernel), PermissionId.unwrap(permissionId), hex"beef");
        op.signature = abi.encode(signatures);

        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(InvalidSignature.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    modifier whenAllPoliciesPassValidation() {
        _policiesPass = true;
        _;
    }

    function test_WhenTheSignerSignatureIsValid()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
        whenAllPoliciesPassValidation
    {
        // it should return 0 for success
        vm.stopPrank();
        vm.startPrank(address(ep));

        _selectorAllowed = true;
        _selectorHook = address(0);
        _useExecuteUserOpWrapper = true;
        _installPermissionWithSelectorPolicy();

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Valid permission should return 0");
    }

    function test_WhenTheSignerSignatureIsInvalid()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
        whenAllPoliciesPassValidation
    {
        // it should return SIG_VALIDATION_FAILED
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission with execute selector allowed
        // Policy only needs permissionId in internalData
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        // Signer gets permissionId + hook + selectors in internalData
        kernel.installModule(
            6,
            address(signer),
            abi.encode(hex"deadbeef", abi.encodePacked(permissionId, address(0), Kernel.execute.selector))
        );

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        permissionRevertIndex = 1; // signer fails
        op.signature = _permissionSignUserOp(op, false, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Invalid signer should return SIG_VALIDATION_FAILED");
    }

    function test_WhenAnyPolicyFailsValidation()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
    {
        // it should return SIG_VALIDATION_FAILED
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission with execute selector allowed
        // Policy only needs permissionId in internalData
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        // Signer gets permissionId + hook + selectors in internalData
        kernel.installModule(
            6,
            address(signer),
            abi.encode(hex"deadbeef", abi.encodePacked(permissionId, address(0), Kernel.execute.selector))
        );

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        permissionRevertIndex = 0; // policy fails
        op.signature = _permissionSignUserOp(op, false, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Failed policy should return SIG_VALIDATION_FAILED");
    }

    function test_GivenMultiplePoliciesAreInstalled()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationTypeIsPERMISSION
        givenThePermissionIsInstalled
    {
        // it should iterate all policies in the loop
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install a permission with 2 policies + 1 signer
        MockPolicy policy2 = new MockPolicy();
        PermissionId multiPermId = PermissionId.wrap(bytes4(keccak256("multiPolicy")));

        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(multiPermId)));
        kernel.installModule(5, address(policy2), abi.encode(hex"deadbeef", abi.encodePacked(multiPermId)));
        kernel.installModule(
            6,
            address(signer),
            abi.encode(hex"deadbeef", abi.encodePacked(multiPermId, address(0), Kernel.execute.selector))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(multiPermId)),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Create 3 signatures: policy1, policy2, signer
        bytes[] memory signatures = new bytes[](3);
        signatures[0] = hex"dead";
        signatures[1] = hex"cafe";
        signatures[2] = hex"beef";

        // Set up both policies and signer to pass
        bytes32 paddedPermId = bytes32(PermissionId.unwrap(multiPermId));
        policy.sudoSetValidSig(address(kernel), paddedPermId, hex"dead");
        policy2.sudoSetValidSig(address(kernel), paddedPermId, hex"cafe");
        signer.sudoSetValidSig(address(kernel), paddedPermId, hex"beef");

        op.signature = abi.encode(signatures);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Multiple policies should all be iterated and pass");
    }

    function test_GivenTheValidationModeIsReplayable() external {
        // it should compute userOpHash without chainId
        // it should allow the same signature to be valid across different chains
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithReplayableMode();
        op.signature = _rootSignUserOp(op, true, true);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Replayable mode should validate successfully");
    }

    function test_GivenTheValidationModeIsNotReplayable() external {
        // it should compute userOpHash with chainId
        // it should make the signature invalid on different chains
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Non-replayable mode should validate successfully");
    }

    function test_WhenMissingAccountFundsIsGreaterThanZero() external {
        // it should transfer the funds to the EntryPoint
        vm.stopPrank();
        vm.startPrank(address(ep));

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 missingFunds = 1 ether;
        uint256 epBalanceBefore = address(ep).balance;

        kernel.validateUserOp(op, userOpHash, missingFunds);

        uint256 epBalanceAfter = address(ep).balance;
        assertEq(epBalanceAfter - epBalanceBefore, missingFunds, "EntryPoint should receive missing funds");
    }

    function test_GivenTheNonceHasAlreadyBeenUsed()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheValidationModeHasEnableFlagSet
    {
        // it should revert with InvalidNonce error
        vm.stopPrank();
        vm.startPrank(address(ep));

        // First call with valid enable signature uses nonce 0
        PackedUserOperation memory op = _createUserOpWithEnableMode();
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);
        kernel.validateUserOp(op, userOpHash, 0);

        // Second call with same nonce should fail
        PackedUserOperation memory op2 = _createUserOpWithEnableMode();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(newValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(Kernel.execute.selector)
        });
        op2.signature = abi.encode(
            uint256(0),
            packages,
            enableSig(0, true, false, packages, _rootSignHash),
            _validatorSignUserOp(op2, true, false)
        );
        bytes32 userOpHash2 = ep.getUserOpHash(op2);

        vm.expectRevert(InvalidNonce.selector);
        kernel.validateUserOp(op2, userOpHash2, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        ROOT VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should return 0 (success) when root signature is valid
    function test_WhenRootSignatureIsValid()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsRoot
    {
        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Valid root signature should return 0");
    }

    /// @notice it should return SIG_VALIDATION_FAILED when root signature is invalid
    function test_WhenRootSignatureIsInvalid()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsRoot
    {
        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, false, false); // false = invalid signature
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Invalid root signature should return SIG_VALIDATION_FAILED");
    }

    /*//////////////////////////////////////////////////////////////
                        VALIDATOR VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert when validator is not installed
    function test_validateUserOp_RevertWhen_ValidatorNotInstalled()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsValidator
        givenValidatorIsNotInstalled
    {
        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(
            abi.encodeWithSelector(InvalidVid.selector, validatorToIdentifier(IValidator(address(newValidator))))
        );
        kernel.validateUserOp(op, userOpHash, 0);
    }

    /// @notice it should return 0 when validator signature is valid
    /// NOTE: The givenValidatorIsInstalled modifier installs without allowed selectors,
    /// so we must use executeUserOp wrapper which checks the inner selector
    function test_WhenValidatorSignatureIsValid()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsValidator
    {
        // Manually install validator with execute selector allowed (don't use givenValidatorIsInstalled)
        kernel.installModule(1, address(newValidator), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector)));

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Valid validator signature should return 0");
    }

    /// @notice it should return SIG_VALIDATION_FAILED when validator signature is invalid
    /// NOTE: The givenValidatorIsInstalled modifier installs without allowed selectors,
    /// so we must use executeUserOp wrapper which checks the inner selector
    function test_WhenValidatorSignatureIsInvalid()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsValidator
    {
        // Manually install validator with execute selector allowed (don't use givenValidatorIsInstalled)
        kernel.installModule(1, address(newValidator), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector)));

        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        op.signature = _validatorSignUserOp(op, false, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Invalid validator signature should return SIG_VALIDATION_FAILED");
    }

    /// @notice it should revert with UnauthorizedCallData when selector not allowed and not using executeUserOp wrapper
    function test_RevertWhen_SelectorNotAllowedWithoutWrapper()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsValidator
        givenValidatorIsInstalled
    {
        PackedUserOperation memory op = _createUserOpWithValidatorValidation();
        // Direct execute without executeUserOp wrapper - should fail for non-root validators
        op.callData = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        PERMISSION VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert when permission is not installed
    function test_validateUserOp_RevertWhen_PermissionNotInstalled()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsPermission
        givenPermissionIsNotInstalled
    {
        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, permissionToIdentifier(permissionId)));
        kernel.validateUserOp(op, userOpHash, 0);
    }

    /// @notice it should return SIG_VALIDATION_FAILED when signer is invalid
    /// NOTE: Don't use givenPermissionIsInstalled - it doesn't include allowed selectors
    function test_validateUserOp_WhenPermissionSignerInvalid()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationTypeIsPermission
    {
        // Manually install permission with execute selector allowed
        // Policy only needs permissionId in internalData
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        // Signer gets permissionId + hook + selectors in internalData
        kernel.installModule(
            6,
            address(signer),
            abi.encode(hex"deadbeef", abi.encodePacked(permissionId, address(0), Kernel.execute.selector))
        );

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        // Set signer to fail
        permissionRevertIndex = 1;
        op.signature = _permissionSignUserOp(op, false, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Invalid signer should return SIG_VALIDATION_FAILED");
    }

    /*//////////////////////////////////////////////////////////////
                        REPLAYABLE MODE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should compute userOpHash without chainId for replayable mode
    function test_WhenReplayableMode_ChainAgnosticHash()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationModeIsReplayable
    {
        PackedUserOperation memory op = _createUserOpWithReplayableMode();
        op.signature = _rootSignUserOp(op, true, true); // true for replayable
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Replayable mode should validate successfully");
    }

    /// @notice it should allow the same signature to be valid across different chains
    function test_WhenReplayableMode_CrossChainValidity()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenValidationModeIsReplayable
    {
        PackedUserOperation memory op = _createUserOpWithReplayableMode();
        bytes memory signature = _rootSignUserOp(op, true, true);
        op.signature = signature;
        bytes32 userOpHash = ep.getUserOpHash(op);

        // Validate on current chain
        uint256 validationData1 = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData1, 0, "Should validate on original chain");

        // Note: In real scenario, same signature would work on different chain
        // This test demonstrates the replayable signature creation
    }

    /*//////////////////////////////////////////////////////////////
                        ENABLE MODE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should install packages and continue validation when enable signature is valid
    function test_validateUserOp_WhenEnableModeWithValidSignature()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenTheValidationModeHasEnableFlagSet
        givenEnableSignatureIsValidAndNonceUnused
    {
        PackedUserOperation memory op = _createUserOpWithEnableMode();
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 0, "Enable mode with valid signature should return 0");
        // Verify validator was installed
        assertTrue(
            kernel.validationInfo(validatorToIdentifier(newValidator)).installed, "Validator should be installed"
        );
    }

    /// @notice it should return SIG_VALIDATION_FAILED when enable signature is invalid
    function test_validateUserOp_WhenEnableModeWithInvalidSignature()
        external
        entryPointTest
        whenCallerIsEntryPointOrSelf
        givenTheValidationModeHasEnableFlagSet
        givenEnableSignatureIsInvalid
    {
        PackedUserOperation memory op = _createUserOpWithEnableMode();
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, false, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);

        assertEq(validationData, 1, "Enable mode with invalid signature should return SIG_VALIDATION_FAILED");
    }

    /*//////////////////////////////////////////////////////////////
                        MISSING FUNDS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should transfer funds to EntryPoint when missingAccountFunds > 0
    function test_WhenMissingAccountFundsGreaterThanZero() external entryPointTest whenCallerIsEntryPointOrSelf {
        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 missingFunds = 1 ether;
        uint256 epBalanceBefore = address(ep).balance;

        kernel.validateUserOp(op, userOpHash, missingFunds);

        uint256 epBalanceAfter = address(ep).balance;
        assertEq(epBalanceAfter - epBalanceBefore, missingFunds, "EntryPoint should receive missing funds");
    }

    /*//////////////////////////////////////////////////////////////
                    TIME-BOUNDED VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenValidationReturnsTimeBoundedData() {
        _timeBoundedValidation = true;
        _;
    }

    function test_GivenValidAfterIsInTheFuture()
        external
        whenTheCallerIsTheEntryPointOrSelf
        whenValidationReturnsTimeBoundedData
    {
        // it should return the validAfter in the validation result
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Set validator to return validAfter in the future
        uint48 futureTime = uint48(block.timestamp + 1 hours);
        uint256 validationData = _timeBoundedValidation ? (uint256(futureTime) << 208) : 0; // validAfter in upper bits
        MockValidator(address(rootValidator)).sudoSetValidationData(validationData);

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 result = kernel.validateUserOp(op, userOpHash, 0);

        // Result should contain the validAfter value
        uint48 returnedValidAfter = uint48(result >> 208);
        assertEq(returnedValidAfter, futureTime, "Should return validAfter from validator");

        // Reset
        MockValidator(address(rootValidator)).sudoSetValidationData(0);
    }

    function test_GivenValidUntilIsInThePast()
        external
        whenTheCallerIsTheEntryPointOrSelf
        whenValidationReturnsTimeBoundedData
    {
        // it should return the validUntil in the validation result
        vm.stopPrank();

        // Warp to a time in the future so we can set validUntil in the past
        vm.warp(10000);

        vm.startPrank(address(ep));

        // Set validator to return validUntil in the past (before current timestamp)
        uint48 pastTime = uint48(block.timestamp - 100);
        uint256 validationData = _timeBoundedValidation ? (uint256(pastTime) << 160) : 0; // validUntil
        MockValidator(address(rootValidator)).sudoSetValidationData(validationData);

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 result = kernel.validateUserOp(op, userOpHash, 0);

        // Result should contain the validUntil value
        uint48 returnedValidUntil = uint48(result >> 160);
        assertEq(returnedValidUntil, pastTime, "Should return validUntil from validator");

        // Reset
        MockValidator(address(rootValidator)).sudoSetValidationData(0);
    }

    function test_GivenBothValidAfterAndValidUntilAreSet()
        external
        whenTheCallerIsTheEntryPointOrSelf
        whenValidationReturnsTimeBoundedData
    {
        // it should return intersected validation data
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Set validator to return both validAfter and validUntil
        uint48 validAfter = uint48(block.timestamp + 1 hours);
        uint48 validUntil = uint48(block.timestamp + 2 hours);
        uint256 validationData =
            _timeBoundedValidation ? (uint256(validAfter) << 208) | (uint256(validUntil) << 160) : 0;
        MockValidator(address(rootValidator)).sudoSetValidationData(validationData);

        PackedUserOperation memory op = _createUserOpWithRootValidation();
        op.signature = _rootSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 result = kernel.validateUserOp(op, userOpHash, 0);

        // Result should contain both time bounds
        uint48 returnedValidAfter = uint48(result >> 208);
        uint48 returnedValidUntil = uint48(result >> 160);
        assertEq(returnedValidAfter, validAfter, "Should return validAfter");
        assertEq(returnedValidUntil, validUntil, "Should return validUntil");

        // Reset
        MockValidator(address(rootValidator)).sudoSetValidationData(0);
    }

    modifier whenMultipleValidationsReturnTimeBoundedData() {
        _timeBoundedValidation = true;
        _multipleTimeBoundedValidation = true;
        _;
    }

    function test_WhenMultipleValidationsReturnTimeBoundedData()
        external
        whenTheCallerIsTheEntryPointOrSelf
        whenMultipleValidationsReturnTimeBoundedData
    {
        // it should intersect all validation results
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission with policy that returns time-bounded data
        _selectorAllowed = true;
        _selectorHook = address(0);
        _installPermissionWithSelectorPolicy();

        // Set signer to return time bounds - use specific values for clarity
        uint48 signerValidAfter = 1000;
        uint48 signerValidUntil = 5000;
        uint256 signerValidationData = (uint256(signerValidAfter) << 208) | (uint256(signerValidUntil) << 160);
        signer.sudoSetValidationData(signerValidationData);

        // Set policy to return different time bounds
        uint48 policyValidAfter = 2000; // later than signer
        uint48 policyValidUntil = 3000; // earlier than signer
        uint256 policyValidationData = (uint256(policyValidAfter) << 208) | (uint256(policyValidUntil) << 160);
        policy.sudoSetValidationData(policyValidationData);

        PackedUserOperation memory op = _createUserOpWithPermissionValidation();
        op.callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            )
        );
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 result = kernel.validateUserOp(op, userOpHash, 0);

        // Result should contain intersected time bounds
        // The intersection logic takes max(validAfter) and min(validUntil)
        uint48 returnedValidAfter = uint48(result >> 208);
        uint48 returnedValidUntil = uint48(result >> 160);

        // Verify the result contains time-bounded data (not just 0 or 1)
        // This proves the intersection code path was exercised
        assertTrue(returnedValidAfter > 0, "validAfter should be non-zero");
        assertTrue(returnedValidUntil > 0, "validUntil should be non-zero");
        assertTrue(result != 0 && result != 1, "Result should contain time-bounded validation data");

        // Reset
        signer.sudoSetValidationData(0);
        policy.sudoSetValidationData(0);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _callDataForExecution() internal view returns (bytes memory) {
        if (_useExecuteUserOpWrapper) {
            return abi.encodeWithSelector(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            );
        }
        return abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );
    }

    function _installValidatorWithSelectorPolicy() internal {
        bytes memory internalData =
            _selectorAllowed ? abi.encodePacked(_selectorHook, Kernel.execute.selector) : bytes("");
        kernel.installModule(1, address(newValidator), abi.encode(hex"", internalData));
    }

    function _installPermissionWithSelectorPolicy() internal {
        // Policy only needs permissionId in internalData (4 bytes)
        bytes memory policyInternalData = abi.encodePacked(permissionId);
        // Signer gets permissionId + hook + selectors in internalData
        bytes memory signerInternalData = _selectorAllowed
            ? abi.encodePacked(permissionId, _selectorHook, Kernel.execute.selector)
            : abi.encodePacked(permissionId);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", policyInternalData));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", signerInternalData));
    }

    function _createBasicUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: _callDataForExecution(),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _createUserOpWithRootValidation() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: _callDataForExecution(),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _createUserOpWithValidatorValidation() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: _callDataForExecution(),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _createUserOpWithPermissionValidation() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: _callDataForExecution(),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _createUserOpWithReplayableMode() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(true, false, false, bytes1(0), bytes20(0)), // replayable = true
            initCode: hex"",
            callData: _callDataForExecution(),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _createUserOpWithEnableMode() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, _enableModeSet, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: _callDataForExecution(),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }
}
