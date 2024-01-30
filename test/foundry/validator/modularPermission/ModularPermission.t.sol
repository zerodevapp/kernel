pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {IKernel} from "src/interfaces/IKernel.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";
import {Operation} from "src/common/Enums.sol";
import "src/validator/modularPermission/ModularPermissionValidator.sol";
import "src/validator/modularPermission/signers/ECDSASigner.sol";
import "src/validator/modularPermission/mock/MockPolicy.sol";
import "src/validator/modularPermission/mock/MockSigner.sol";
import "forge-std/Test.sol";
import {KernelTestBase} from "src/utils/KernelTestBase.sol";
import {TestExecutor} from "src/mock/TestExecutor.sol";
import {TestValidator} from "src/mock/TestValidator.sol";
import {KernelStorage} from "src/abstract/KernelStorage.sol";
import {ERC4337Utils} from "src/utils/ERC4337Utils.sol";
import {SignaturePolicy} from "src/validator/modularPermission/SignaturePolicy.sol";

using ERC4337Utils for IEntryPoint;

contract ModularPermissionE2ETest is KernelTestBase {
    ECDSASigner signer;
    MockPolicy mockPolicy;
    SignaturePolicy signaturePolicy;
    bytes32 permissionId;
    address[] allowedCaller;

    function setUp() public virtual {
        _initialize();
        defaultValidator = new ModularPermissionValidator();
        signer = new ECDSASigner();
        mockPolicy = new MockPolicy();
        signaturePolicy = new SignaturePolicy();
        allowedCaller = new address[](2);
        allowedCaller[0] = makeAddr("app");
        allowedCaller[1] = address(0);
        _setAddress();
        _setExecutionDetail();
    }

    function test_ignore() external {}

    function getPermissionId() internal view returns (bytes32) {
        PolicyConfig[] memory p = new PolicyConfig[](2);
        p[0] = PolicyConfigLib.pack(IPolicy(address(mockPolicy)), toFlag(0));
        p[1] = PolicyConfigLib.pack(IPolicy(address(signaturePolicy)), toFlag(1));
        bytes[] memory pd = new bytes[](2);
        pd[0] = abi.encodePacked("policy data 1");
        pd[1] = abi.encode(allowedCaller);

        return ModularPermissionValidator(address(defaultValidator)).getPermissionId(
            0, MAX_FLAG, signer, ValidAfter.wrap(0), ValidUntil.wrap(0), p, abi.encodePacked(owner), pd
        );
    }

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function getValidatorSignature(UserOperation memory) internal view virtual override returns (bytes memory) {
        return "";
    }

    function getOwners() internal view override returns (address[] memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return owners;
    }

    function getInitializeData() internal view override returns (bytes memory) {
        bytes memory sd = abi.encodePacked(owner);
        PolicyConfig[] memory p = new PolicyConfig[](2);
        p[0] = PolicyConfigLib.pack(IPolicy(address(mockPolicy)), toFlag(0));
        p[1] = PolicyConfigLib.pack(IPolicy(address(signaturePolicy)), toFlag(1));
        bytes[] memory pd = new bytes[](2);
        pd[0] = abi.encodePacked("policy data 1");
        pd[1] = abi.encode(allowedCaller);
        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG,
                uint48(0), //`validAfter
                uint48(0), // validUntil
                address(signer)
            ), // signer
            abi.encode(p, sd, pd)
        );

        return abi.encodeWithSelector(KernelStorage.initialize.selector, defaultValidator, data);
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), getPermissionId(), entryPoint.signUserOpHash(vm, ownerKey, op));
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), getPermissionId(), entryPoint.signUserOpHash(vm, ownerKey + 1, op));
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(getPermissionId(), r, s, v);
    }

    function getWrongSignature(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey + 1, hash);
        return abi.encodePacked(getPermissionId(), r, s, v);
    }

    function test_default_validator_enable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(IKernelValidator.enable.selector, abi.encodePacked(address(0xdeadbeef))),
                Operation.Call
            )
        );
        bytes memory sd = abi.encodePacked(owner);
        PolicyConfig[] memory p = new PolicyConfig[](1);
        p[0] = PolicyConfigLib.pack(IPolicy(address(mockPolicy)), toFlag(0));
        bytes[] memory pd = new bytes[](1);
        pd[0] = abi.encodePacked("policy data 2");
        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG, //flag
                uint48(0), //`validAfter
                uint48(0), // validUntil
                address(signer)
            ), // signer
            abi.encode(p, sd, pd)
        );
        performUserOperationWithSig(op);
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(IKernelValidator.disable.selector, abi.encodePacked(getPermissionId())),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
    }

    function test_external_call_execute_success() external override {
        vm.skip(true);
    }

    function test_external_call_default() external override {
        vm.skip(true);
    }

    function test_external_call_execute_delegatecall_success() external override {
        vm.skip(true);
    }

    function test_external_call_batch_execute_success() external override {
        vm.skip(true);
    }

    function test_external_call_execution() external override {
        vm.skip(true);
    }
}

contract ModularPermissionUnitTest is Test {
    ModularPermissionValidator validator;

    MockSigner mockSigner;
    MockPolicy mockPolicy;

    function setUp() external {
        validator = new ModularPermissionValidator();
        mockPolicy = new MockPolicy();
        mockSigner = new MockSigner();
    }

    function testParseData() external {
        uint48 until = uint48(block.timestamp + 100);
        bytes memory sd = abi.encodePacked("hello world");
        PolicyConfig[] memory p = new PolicyConfig[](2);
        p[0] = PolicyConfigLib.pack(IPolicy(address(0xdeadbeef)), toFlag(0));
        p[1] = PolicyConfigLib.pack(IPolicy(address(0xcafecafe)), toFlag(0));
        bytes[] memory pd = new bytes[](2);
        pd[0] = abi.encodePacked("policy data 1");
        pd[1] = abi.encodePacked("policy data 2");
        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG, //flag
                uint48(1), //`validAfter
                until, // validUntil
                address(0xdead)
            ), // signer
            abi.encode(p, sd, pd)
        );
        (
            uint128 nonce,
            bytes12 flag,
            ISigner signer,
            ValidAfter validAfter,
            ValidUntil validUntil,
            PolicyConfig[] memory policies,
            bytes memory signerData,
            bytes[] memory policyData
        ) = validator.parseData(data);
        assertEq(nonce, uint128(0));
        assertEq(flag, MAX_FLAG);
        assertEq(ValidAfter.unwrap(validAfter), uint48(1));
        assertEq(ValidUntil.unwrap(validUntil), until);
        assertEq(address(signer), address(0xdead));
        assertEq(address(PolicyConfigLib.getAddress(policies[0])), address(0xdeadbeef));
        assertEq(address(PolicyConfigLib.getAddress(policies[1])), address(0xcafecafe));
        assertEq(signerData, abi.encodePacked("hello world"));
        assertEq(policyData[0], abi.encodePacked("policy data 1"));
        assertEq(policyData[1], abi.encodePacked("policy data 2"));
    }

    function testRegister() external {
        uint48 until = uint48(block.timestamp + 100);
        bytes memory sd = abi.encodePacked("hello signer");
        PolicyConfig[] memory p = new PolicyConfig[](1);
        p[0] = PolicyConfigLib.pack(IPolicy(address(mockPolicy)), toFlag(0));
        bytes[] memory pd = new bytes[](1);
        pd[0] = abi.encodePacked("hello policy");
        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG, //flag
                uint48(1), //`validAfter
                until, // validUntil
                address(mockSigner)
            ), // signer
            abi.encode(p, sd, pd)
        );
        validator.enable(data);
    }

    struct ModularPermissionConfig {
        uint128 nonce;
        bytes12 flag;
        ISigner signer;
        ValidAfter validAfter;
        ValidUntil validUntil;
        PolicyConfig firstPolicy;
    }

    function testValidateUserOpSkip() external {
        address kernel = makeAddr("Kernel");
        ValidUntil until = ValidUntil.wrap(uint48(block.timestamp + 100));
        bytes memory sd = abi.encodePacked("hello signer");
        MockPolicy skipPolicy = new MockPolicy();
        PolicyConfig[] memory p = new PolicyConfig[](2);
        p[0] = PolicyConfigLib.pack(mockPolicy, toFlag(0));
        p[1] = PolicyConfigLib.pack(skipPolicy, toFlag(1)); // skip

        bytes[] memory pd = new bytes[](2);
        pd[0] = abi.encodePacked("hello policy");
        pd[1] = abi.encodePacked("hello policy 2");
        bytes32 permissionId = validator.getPermissionId(
            0,
            MAX_FLAG, //flag
            mockSigner,
            ValidAfter.wrap(1),
            until,
            p,
            sd,
            pd
        );

        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG, //flag
                uint48(1), //`validAfter
                until, // validUntil
                address(mockSigner)
            ), // signer
            abi.encode(p, sd, pd)
        );
        vm.startPrank(kernel);
        validator.enable(data);
        vm.stopPrank();

        ModularPermissionConfig memory config;

        (config.nonce, config.flag, config.signer, config.firstPolicy, config.validAfter, config.validUntil) =
            validator.permissions(permissionId, kernel);
        assertEq(config.nonce, uint128(0));
        assertEq(config.flag, MAX_FLAG);
        assertEq(ValidAfter.unwrap(config.validAfter), uint48(1));
        assertEq(ValidUntil.unwrap(config.validUntil), ValidUntil.unwrap(until));
        assertEq(address(config.signer), address(mockSigner));
        assertEq(address(PolicyConfigLib.getAddress(config.firstPolicy)), address(mockPolicy));

        assertEq(mockSigner.signerData(), sd);
        assertEq(mockPolicy.policyData(), pd[0]);
        UserOperation memory op;
        op.sender = kernel;
        op.signature = abi.encodePacked(permissionId);
        vm.startPrank(kernel);
        validator.validateUserOp(op, keccak256(abi.encodePacked("hello")), 0);
        vm.stopPrank();

        assertEq(mockSigner.count(permissionId), 1);
        assertEq(mockPolicy.count(permissionId), 1);
        assertEq(skipPolicy.count(permissionId), 0);
    }

    function testValidateSignatureSkip() external {
        address kernel = makeAddr("Kernel");
        ValidUntil until = ValidUntil.wrap(uint48(block.timestamp + 100));
        bytes memory sd = abi.encodePacked("hello signer");
        MockPolicy skipPolicy = new MockPolicy();
        PolicyConfig[] memory p = new PolicyConfig[](2);
        p[0] = PolicyConfigLib.pack(mockPolicy, toFlag(0));
        p[1] = PolicyConfigLib.pack(skipPolicy, toFlag(2)); // skip on signature
        skipPolicy.mock(0, 0, true, true);

        bytes[] memory pd = new bytes[](2);
        pd[0] = abi.encodePacked("hello policy");
        pd[1] = abi.encodePacked("hello policy 2");
        bytes32 permissionId = validator.getPermissionId(
            0,
            MAX_FLAG, //flag
            mockSigner,
            ValidAfter.wrap(1),
            until,
            p,
            sd,
            pd
        );

        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG, //flag
                uint48(1), //`validAfter
                until, // validUntil
                address(mockSigner)
            ), // signer
            abi.encode(p, sd, pd)
        );
        vm.startPrank(kernel);
        validator.enable(data);
        vm.stopPrank();

        ModularPermissionConfig memory config;

        (config.nonce, config.flag, config.signer, config.firstPolicy, config.validAfter, config.validUntil) =
            validator.permissions(permissionId, kernel);
        assertEq(config.nonce, uint128(0));
        assertEq(config.flag, MAX_FLAG);
        assertEq(ValidAfter.unwrap(config.validAfter), uint48(1));
        assertEq(ValidUntil.unwrap(config.validUntil), ValidUntil.unwrap(until));
        assertEq(address(config.signer), address(mockSigner));
        assertEq(address(PolicyConfigLib.getAddress(config.firstPolicy)), address(mockPolicy));

        assertEq(mockSigner.signerData(), sd);
        assertEq(mockPolicy.policyData(), pd[0]);
        UserOperation memory op;
        op.sender = kernel;
        op.signature = abi.encodePacked(permissionId);
        vm.startPrank(kernel);
        vm.expectRevert();
        validator.validateSignature(keccak256(abi.encodePacked("hello")), "");
        vm.stopPrank();
    }

    function testValidateUserOp() external {
        address kernel = makeAddr("Kernel");
        ValidUntil until = ValidUntil.wrap(uint48(block.timestamp + 100));
        bytes memory sd = abi.encodePacked("hello signer");
        PolicyConfig[] memory p = new PolicyConfig[](1);
        p[0] = PolicyConfigLib.pack(mockPolicy, toFlag(0));
        bytes[] memory pd = new bytes[](1);
        pd[0] = abi.encodePacked("hello policy");
        bytes32 permissionId = validator.getPermissionId(
            0,
            MAX_FLAG, //flag
            mockSigner,
            ValidAfter.wrap(1),
            until,
            p,
            sd,
            pd
        );

        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                MAX_FLAG, //flag
                uint48(1), //`validAfter
                until, // validUntil
                address(mockSigner)
            ), // signer
            abi.encode(p, sd, pd)
        );
        vm.startPrank(kernel);
        validator.enable(data);
        vm.stopPrank();

        (
            uint128 nonce,
            bytes12 flag,
            ISigner signer,
            PolicyConfig firstPolicy,
            ValidAfter validAfter,
            ValidUntil validUntil
        ) = validator.permissions(permissionId, kernel);
        assertEq(nonce, uint128(0));
        assertEq(flag, MAX_FLAG);
        assertEq(ValidAfter.unwrap(validAfter), uint48(1));
        assertEq(ValidUntil.unwrap(validUntil), ValidUntil.unwrap(until));
        assertEq(address(signer), address(mockSigner));
        assertEq(address(PolicyConfigLib.getAddress(firstPolicy)), address(mockPolicy));

        assertEq(mockSigner.signerData(), sd);
        assertEq(mockPolicy.policyData(), pd[0]);
        UserOperation memory op;
        op.sender = kernel;
        op.signature = abi.encodePacked(permissionId);
        vm.startPrank(kernel);
        validator.validateUserOp(op, keccak256(abi.encodePacked("hello")), 0);
        vm.stopPrank();

        assertEq(mockSigner.count(permissionId), 1);
        assertEq(mockPolicy.count(permissionId), 1);
    }
}
