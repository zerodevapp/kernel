// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/factory/KernelFactory.sol";
import "src/factory/FactoryStaker.sol";
import "forge-std/Test.sol";
import "src/mock/MockValidator.sol";
import "src/mock/MockPolicy.sol";
import "src/mock/MockSigner.sol";
import "src/mock/MockAction.sol";
import "src/mock/MockHook.sol";
import "src/mock/MockExecutor.sol";
import "src/mock/MockFallback.sol";
import "src/core/ValidationManager.sol";
import "./erc4337Util.sol";

contract MockCallee {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}

abstract contract KernelTestBase is Test {
    address stakerOwner;
    Kernel kernel;
    KernelFactory factory;
    FactoryStaker staker;
    IEntryPoint entrypoint;
    ValidationId rootValidation;

    struct RootValidationConfig {
        IHook hook;
        bytes validatorData;
        bytes hookData;
    }

    RootValidationConfig rootValidationConfig;
    MockValidator mockValidator;
    MockCallee callee;
    MockHook mockHook;

    IValidator enabledValidator;
    EnableValidatorConfig validationConfig;

    struct EnableValidatorConfig {
        IHook hook;
        bytes hookData;
        bytes validatorData;
    }

    PermissionId enabledPermission;
    EnablePermissionConfig permissionConfig;

    struct EnablePermissionConfig {
        IHook hook;
        bytes hookData;
        IPolicy[] policies;
        bytes[] policyData;
        ISigner signer;
        bytes signerData;
    }

    modifier whenInitialized() {
        address deployed = factory.createAccount(initData(), bytes32(0));
        assertEq(deployed, address(kernel));
        assertEq(kernel.currentNonce(), 1);
        _;
    }

    function setUp() public {
        enabledPermission = PermissionId.wrap(bytes4(0xdeadbeef));
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entrypoint);
        factory = new KernelFactory(address(impl));
        callee = new MockCallee();
        mockHook = new MockHook();
        _setRootValidationConfig();
        _setEnableValidatorConfig();
        _setEnablePermissionConfig();
        kernel = Kernel(payable(factory.getAddress(initData(), bytes32(0))));
        stakerOwner = makeAddr("StakerOwner");
        staker = new FactoryStaker(stakerOwner);
        vm.startPrank(stakerOwner);
        staker.approveFactory(factory, true);
        vm.stopPrank();
    }

    function testDeployWithFactory() external {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            hex"", true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function initData() internal view returns(bytes memory) {
        return abi.encodeWithSelector(
            Kernel.initialize.selector,
            rootValidation,
            rootValidationConfig.hook,
            rootValidationConfig.validatorData,
            rootValidationConfig.hookData
        );
    }

    // things to override on test
    function _setRootValidationConfig() internal virtual {
        mockValidator = new MockValidator();
        rootValidation = ValidatorLib.validatorToIdentifier(mockValidator);
    }

    function _setEnableValidatorConfig() internal virtual {
        enabledValidator = new MockValidator();
    }

    function _setEnablePermissionConfig() internal virtual {
        IPolicy[] memory policies = new IPolicy[](2);
        MockPolicy mockPolicy = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        policies[0] = mockPolicy;
        policies[1] = mockPolicy2;
        bytes[] memory policyData = new bytes[](2);
        policyData[0] = "policy1";
        policyData[1] = "policy2";
        MockSigner mockSigner = new MockSigner();

        permissionConfig.policies = policies;
        permissionConfig.signer = mockSigner;
        permissionConfig.policyData = policyData;
        permissionConfig.signerData = "signer";
    }

    // root validator cases
    function _rootValidatorSuccessCheck() internal virtual {
        assertEq(123, callee.value());
    }

    function _rootValidatorFailureCheck() internal virtual {
        assertEq(0, callee.value());
    }

    function _prepareRootUserOp(bytes memory callData, bool success) internal returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), 0),
            initCode: address(kernel).code.length == 0 ? abi.encodePacked(address(staker), abi.encodeWithSelector(staker.deployWithFactory.selector, factory, initData(), bytes32(0))) : abi.encodePacked(hex""),
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        op.signature = _rootSignUserOp(op, success);
    }

    function _rootSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        if (success) {
            data = "enableSig";
            mockValidator.sudoSetValidSig(data);
        } else {
            data = "failEnableSig";
        }
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success) internal virtual returns (bytes memory) {
        mockValidator.sudoSetSuccess(success);
        return success ? abi.encodePacked("success") : abi.encodePacked("failure");
    }

    function _validatorSignUserOp(PackedUserOperation memory, bool success)
        internal
        virtual
        returns (bytes memory data)
    {
        MockValidator(address(enabledValidator)).sudoSetSuccess(success);
        if (success) {
            return "userOpSig";
        } else {
            return "failUserOpSig";
        }
    }

    function _validatorSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        if (success) {
            data = "enableSig";
            MockValidator(address(enabledValidator)).sudoSetValidSig(data);
        } else {
            data = "failEnableSig";
        }
    }

    function _permissionSignUserOp(PackedUserOperation memory op, bool success)
        internal
        virtual
        returns (bytes memory data)
    {
        MockPolicy(address(permissionConfig.policies[0])).sudoSetValidSig(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), "policy1"
        );
        MockPolicy(address(permissionConfig.policies[1])).sudoSetValidSig(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), "policy2"
        );
        MockSigner(address(permissionConfig.signer)).sudoSetValidSig(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), abi.encodePacked("userOpSig")
        );
        bytes[] memory sigs = _getPolicyAndSignerSig(op, success);
        for (uint8 i = 0; i < sigs.length - 1; i++) {
            if (sigs[i].length > 0) {
                data = abi.encodePacked(data, bytes1(i), bytes8(uint64(sigs[i].length)), sigs[i]);
            }
        }
        data = abi.encodePacked(data, bytes1(0xff), sigs[sigs.length - 1]);
    }

    function _permissionSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        MockPolicy(address(permissionConfig.policies[0])).sudoSetPass(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), true
        );
        MockPolicy(address(permissionConfig.policies[1])).sudoSetPass(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), true
        );
        MockSigner(address(permissionConfig.signer)).sudoSetPass(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), true
        );
        return "hello world";
    }

    function _getPolicyAndSignerSig(PackedUserOperation memory op, bool success)
        internal
        returns (bytes[] memory data)
    {
        data = new bytes[](3);
        data[0] = "policy1";
        data[1] = "policy2";
        data[2] = "userOpSig";
    }

    function testRootValidateUserOpSuccess() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)), true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        _rootValidatorSuccessCheck();
    }

    function testRootValidateUserOpFail() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)), false
        );
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function encodeEnableSignature(
        IHook hook,
        bytes memory validatorData,
        bytes memory hookData,
        bytes memory selectorData,
        bytes memory enableSig,
        bytes memory userOpSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encodePacked(hook), abi.encode(validatorData, hookData, selectorData, enableSig, userOpSig)
        );
    }

    function _prepareValidatorEnableUserOp(bytes memory callData) internal returns (PackedUserOperation memory op) {
        uint192 encodedAsNonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(enabledValidator)),
            0 // parallel key
        );
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), encodedAsNonceKey),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 hash = keccak256(
            abi.encode(
                keccak256(
                    "Enable(bytes21 validationId,uint32 nonce,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                ),
                ValidationId.unwrap(ValidatorLib.validatorToIdentifier(enabledValidator)),
                uint256(kernel.currentNonce()),
                validationConfig.hook,
                keccak256(validationConfig.validatorData),
                keccak256(abi.encodePacked(bytes1(0xff), validationConfig.hookData)),
                keccak256(abi.encodePacked(kernel.execute.selector))
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.0-beta", address(kernel)), hash)
        );
        op.signature = encodeEnableSignature(
            validationConfig.hook,
            validationConfig.validatorData,
            abi.encodePacked(bytes1(0xff), validationConfig.hookData),
            abi.encodePacked(kernel.execute.selector),
            _rootSignDigest(digest, true),
            _validatorSignUserOp(op, true)
        );
    }

    function _buildDomainSeparator(string memory name, string memory version, address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

        return keccak256(abi.encode(typeHash, hashedName, hashedVersion, block.chainid, address(verifyingContract)));
    }

    function _preparePermissionEnableUserOp(bytes memory callData) internal returns (PackedUserOperation memory op) {
        uint192 encodedAsNonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(PermissionId.unwrap(enabledPermission)), // permission id
            0
        );
        assertEq(kernel.currentNonce(), 1);
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), encodedAsNonceKey),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 hash = keccak256(
            abi.encode(
                keccak256(
                    "Enable(bytes21 validationId,uint32 nonce,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                ),
                ValidationId.unwrap(ValidatorLib.permissionToIdentifier(enabledPermission)),
                uint256(kernel.currentNonce()),
                permissionConfig.hook,
                keccak256(encodePermissionsEnableData()),
                keccak256(abi.encodePacked(bytes1(0xff), permissionConfig.hookData)),
                keccak256(abi.encodePacked(kernel.execute.selector))
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.0-beta", address(kernel)), hash)
        );
        op.signature = encodeEnableSignature(
            permissionConfig.hook,
            encodePermissionsEnableData(),
            abi.encodePacked(bytes1(0xff), permissionConfig.hookData), // to force call the hook.onInstall()
            abi.encodePacked(kernel.execute.selector),
            _rootSignDigest(digest, true),
            _permissionSignUserOp(op, true)
        );
    }

    function encodeExecute(address _to, uint256 _amount, bytes memory _data) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            kernel.execute.selector, ExecLib.encodeSimpleSingle(), ExecLib.encodeSingle(_to, _amount, _data)
        );
    }

    function testValidateUserOpSuccessValidatorEnableMode() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareValidatorEnableUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        ValidationManager.ValidationConfig memory config =
            kernel.validationConfig(ValidatorLib.validatorToIdentifier(enabledValidator));
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
        assertEq(kernel.currentNonce(), 1);
    }

    function encodePermissionsEnableData() internal returns (bytes memory) {
        bytes[] memory permissions = new bytes[](permissionConfig.policies.length + 1);
        for (uint256 i = 0; i < permissions.length - 1; i++) {
            permissions[i] = abi.encodePacked(
                PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(permissionConfig.policies[i]))),
                permissionConfig.policyData[i]
            );
        }
        permissions[permissions.length - 1] = abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(permissionConfig.signer))),
            permissionConfig.signerData
        );
        return abi.encode(permissions);
    }

    function testValidateUserOpSuccessPermissionEnableMode() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _preparePermissionEnableUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(kernel.currentNonce(), 1);
        assertEq(
            MockSigner(address(permissionConfig.signer)).data(address(kernel)),
            abi.encodePacked(bytes32(PermissionId.unwrap(enabledPermission)), "signer")
        );
    }

    function testActionInstall() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockAction mockAction = new MockAction();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                3,
                address(mockAction),
                abi.encodePacked(MockAction.doSomething.selector, address(0), abi.encode(hex"ff", hex""))
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockAction.doSomething.selector);
        assertEq(address(config.hook), address(1));
        vm.expectEmit(address(kernel));
        emit MockAction.MockActionEvent(address(kernel));
        MockAction(address(kernel)).doSomething();
    }

    function testActionInstallWithHook() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockAction mockAction = new MockAction();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                3,
                address(mockAction),
                abi.encodePacked(
                    MockAction.doSomething.selector,
                    address(mockHook),
                    abi.encode(hex"ff", abi.encodePacked(bytes1(0xff), "hookData"))
                )
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));

        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockAction.doSomething.selector);
        assertEq(address(config.hook), address(mockHook));

        vm.expectEmit(address(kernel));
        emit MockAction.MockActionEvent(address(kernel));
        MockAction(address(kernel)).doSomething();
        assertEq(
            mockHook.preHookData(address(kernel)), abi.encodePacked(address(this), MockAction.doSomething.selector)
        );
        assertEq(mockHook.postHookData(address(kernel)), abi.encodePacked("hookData"));
    }

    function testFallbackInstall() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockFallback mockFallback = new MockFallback();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                3,
                address(mockFallback),
                abi.encodePacked(
                    MockFallback.fallbackFunction.selector,
                    address(0),
                    abi.encode(abi.encodePacked(hex"00", "fallbackData"), abi.encodePacked(""))
                )
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockFallback.data(address(kernel)), abi.encodePacked("fallbackData"));

        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(config.hook), address(1));
        assertEq(address(config.target), address(mockFallback));

        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(MockFallback.fallbackFunction.selector, uint256(10)));
        assertTrue(success);
        (uint256 res) = abi.decode(result, (uint256));
        assertEq(res, 100);
    }

    function testFallbackInstallWithHook() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockFallback mockFallback = new MockFallback();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                3,
                address(mockFallback),
                abi.encodePacked(
                    MockFallback.fallbackFunction.selector,
                    address(mockHook),
                    abi.encode(abi.encodePacked(hex"00", "fallbackData"), abi.encodePacked(bytes1(0xff), "hookData"))
                )
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockFallback.data(address(kernel)), abi.encodePacked("fallbackData"));

        assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));

        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(config.hook), address(mockHook));
        assertEq(address(config.target), address(mockFallback));

        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(MockFallback.fallbackFunction.selector, uint256(10)));
        assertTrue(success);
        (uint256 res) = abi.decode(result, (uint256));
        assertEq(res, 100);
        assertEq(
            mockHook.preHookData(address(kernel)),
            abi.encodePacked(address(this), MockFallback.fallbackFunction.selector, uint256(10))
        );
        assertEq(mockHook.postHookData(address(kernel)), abi.encodePacked("hookData"));
    }

    function testExecutorInstall() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockExecutor mockExecutor = new MockExecutor();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                2,
                address(mockExecutor),
                abi.encodePacked(address(0), abi.encode(abi.encodePacked("executorData"), abi.encodePacked("")))
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockExecutor.data(address(kernel)), abi.encodePacked("executorData"));
        ExecutorManager.ExecutorConfig memory config = kernel.executorConfig(mockExecutor);
        assertEq(address(config.hook), address(1));

        ExecMode mode = ExecLib.encodeSimpleSingle();
        bytes memory data =
            ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(MockCallee.setValue.selector, 123));
        mockExecutor.sudoDoExec(IERC7579Account(kernel), mode, data);
        assertEq(callee.value(), 123);
    }

    function testExecutorInstallWithHook() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockExecutor mockExecutor = new MockExecutor();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                2,
                address(mockExecutor),
                abi.encodePacked(
                    address(mockHook),
                    abi.encode(abi.encodePacked("executorData"), abi.encodePacked(bytes1(0xff), "hookData"))
                )
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        ExecutorManager.ExecutorConfig memory config = kernel.executorConfig(mockExecutor);
        assertEq(address(config.hook), address(mockHook));

        assertEq(mockExecutor.data(address(kernel)), abi.encodePacked("executorData"));

        assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));
        ExecMode mode = ExecLib.encodeSimpleSingle();
        bytes memory data =
            ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(MockCallee.setValue.selector, 123));
        mockExecutor.sudoDoExec(IERC7579Account(kernel), mode, data);
        assertEq(callee.value(), 123);

        assertEq(
            mockHook.preHookData(address(kernel)),
            abi.encodePacked(
                address(mockExecutor), abi.encodeWithSelector(Kernel.executeFromExecutor.selector, mode, data)
            )
        );
        assertEq(mockHook.postHookData(address(kernel)), abi.encodePacked("hookData"));
    }

    function testSignatureRoot(bytes32 hash) external whenInitialized {
        bytes32 wrappedHash = keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.0-beta", address(kernel)), wrappedHash)
        );
        bytes memory sig = _rootSignDigest(digest, true);
        sig = abi.encodePacked(hex"00", sig);
        bytes4 res = kernel.isValidSignature(hash, sig);
        assertEq(res, bytes4(0x1626ba7e));
    }

    function testSignatureValidator(bytes32 hash) external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareValidatorEnableUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        ValidationManager.ValidationConfig memory config =
            kernel.validationConfig(ValidatorLib.validatorToIdentifier(enabledValidator));
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
        assertEq(kernel.currentNonce(), 1);

        bytes32 wrappedHash = keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.0-beta", address(kernel)), wrappedHash)
        );
        bytes memory sig = _validatorSignDigest(digest, true);
        sig = abi.encodePacked(hex"01", address(enabledValidator), sig);
        bytes4 res = kernel.isValidSignature(hash, sig);
        assertEq(res, bytes4(0x1626ba7e));
    }

    function testSignaturePermission(bytes32 hash) external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _preparePermissionEnableUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(kernel.currentNonce(), 1);
        assertEq(
            MockSigner(address(permissionConfig.signer)).data(address(kernel)),
            abi.encodePacked(bytes32(bytes4(0xdeadbeef)), "signer")
        );
        bytes32 wrappedHash = keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.0-beta", address(kernel)), wrappedHash)
        );
        bytes memory sig = _permissionSignDigest(digest, true);
        sig = abi.encodePacked(hex"02", PermissionId.unwrap(enabledPermission), hex"ff", sig);
        bytes4 res = kernel.isValidSignature(hash, sig);
        assertEq(res, bytes4(0x1626ba7e));
    }
}
