// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
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

contract SimpleProxy {
    bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _target) {
        assembly {
            sstore(IMPLEMENTATION_SLOT, _target)
        }
    }

    function _getImplementation() internal view returns (address target) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            target := sload(slot)
        }
    }

    receive() external payable {
        (bool success,) = _getImplementation().delegatecall("");
        require(success, "delegatecall failed");
    }

    fallback(bytes calldata) external payable returns (bytes memory) {
        (bool success, bytes memory ret) = _getImplementation().delegatecall(msg.data);
        require(success, "delegatecall failed");
        return ret;
    }
}

contract MockCallee {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}

abstract contract KernelTestBase is Test {
    Kernel kernel;
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
    // todo selectorData

    modifier whenInitialized() {
        kernel.initialize(
            rootValidation, rootValidationConfig.hook, rootValidationConfig.validatorData, rootValidationConfig.hookData
        );
        assertEq(kernel.currentNonce(), 2);
        _;
    }

    function setUp() public {
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entrypoint);
        callee = new MockCallee();
        kernel = Kernel(payable(address(new SimpleProxy(address(impl)))));
        mockHook = new MockHook();
        _setRootValidationConfig();
        _setEnableValidatorConfig();
        _setEnablePermissionConfig();
    }

    // things to override on test
    function _setRootValidationConfig() internal {
        mockValidator = new MockValidator();
        rootValidation = ValidatorLib.validatorToIdentifier(mockValidator);
    }

    function _setEnableValidatorConfig() internal {
        enabledValidator = new MockValidator();
    }

    function _setEnablePermissionConfig() internal {
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

    // kernel initialize scenario
    function testInitialize() external {
        ValidationId vId = ValidatorLib.validatorToIdentifier(mockValidator);

        kernel.initialize(vId, IHook(address(0)), hex"", hex"");
        assertTrue(kernel.rootValidator() == vId);
        ValidationManager.ValidationConfig memory config;
        config = kernel.validationConfig(vId);
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
        assertEq(mockValidator.isInitialized(address(kernel)), true);
        assertEq(kernel.currentNonce(), 2);
    }

    // root validator cases
    function _rootValidatorFailurePreCondition() internal virtual {
        mockValidator.sudoSetSuccess(false);
    }

    function _rootValidatorSuccessPreCondition() internal virtual {
        mockValidator.sudoSetSuccess(true);
    }

    function _rootValidatorSignature(PackedUserOperation memory op, bool success)
        internal
        view
        virtual
        returns (bytes memory)
    {
        return success ? abi.encodePacked("success") : abi.encodePacked("failure");
    }

    function _rootValidatorSuccessCheck() internal virtual {
        assertEq(123, callee.value());
    }

    function _rootValidatorFailureCheck() internal virtual {
        assertEq(0, callee.value());
    }

    function _prepareRootUserOp(bytes memory callData, bool success) internal returns (PackedUserOperation memory op) {
        if (success) {
            _rootValidatorSuccessPreCondition();
        } else {
            _rootValidatorFailurePreCondition();
        }
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), 0),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: _rootValidatorSignature(op, success)
        });
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

    function getEnableSig(bytes32 digest, bool success) internal returns (bytes memory data) {
        if (success) {
            return "enableSig";
        } else {
            return "failEnableSig";
        }
    }

    function getValidatorSig(PackedUserOperation memory, bool success) internal returns (bytes memory data) {
        if (success) {
            return "userOpSig";
        } else {
            return "failUserOpSig";
        }
    }

    function getPermissionSig(PackedUserOperation memory op, bool success) internal returns (bytes memory data) {
        bytes[] memory sigs = _getPolicyAndSignerSig(op, success);
        for (uint8 i = 0; i < sigs.length - 1; i++) {
            if (sigs[i].length > 0) {
                data = abi.encodePacked(data, bytes1(i), bytes8(uint64(sigs[i].length)), sigs[i]);
            }
        }
        data = abi.encodePacked(data, bytes1(0xff), sigs[sigs.length - 1]);
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

    function _enableValidatorSuccessPreCondition() internal {
        MockValidator(address(enabledValidator)).sudoSetSuccess(true);
        mockValidator.sudoSetValidSig(abi.encodePacked("enableSig"));
    }

    function _enablePermissionSuccessPreCondition() internal {
        MockPolicy(address(permissionConfig.policies[0])).sudoSetValidSig(
            address(kernel), bytes32(bytes4(0xdeadbeef)), "policy1"
        );
        MockPolicy(address(permissionConfig.policies[1])).sudoSetValidSig(
            address(kernel), bytes32(bytes4(0xdeadbeef)), "policy2"
        );
        MockSigner(address(permissionConfig.signer)).sudoSetValidSig(
            address(kernel), bytes32(bytes4(0xdeadbeef)), abi.encodePacked("userOpSig")
        );
        mockValidator.sudoSetValidSig(abi.encodePacked("enableSig"));
    }

    function _prepareValidatorEnableUserOp(bytes memory callData) internal returns (PackedUserOperation memory op) {
        _rootValidatorSuccessPreCondition();
        _enableValidatorSuccessPreCondition();
        uint192 encodedAsNonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(enabledValidator)),
            0
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
            signature: encodeEnableSignature(
                validationConfig.hook,
                validationConfig.validatorData,
                abi.encodePacked(bytes1(0xff), validationConfig.hookData),
                abi.encodePacked(kernel.execute.selector),
                getEnableSig(bytes32(0), true),
                getValidatorSig(op, true)
                )
        });
    }

    function _preparePermissionEnableUserOp(bytes memory callData) internal returns (PackedUserOperation memory op) {
        uint192 encodedAsNonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(bytes4(0xdeadbeef)), // permission id
            0
        );
        assertEq(kernel.currentNonce(), 2);
        _rootValidatorSuccessPreCondition();
        _enablePermissionSuccessPreCondition();
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), encodedAsNonceKey),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: encodeEnableSignature(
                permissionConfig.hook,
                encodePermissionsEnableData(),
                abi.encodePacked(bytes1(0xff), permissionConfig.hookData), // to force call the hook.onInstall()
                abi.encodePacked(kernel.execute.selector),
                getEnableSig(bytes32(0), true),
                getPermissionSig(op, true)
                )
        });
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
        assertEq(config.nonce, 2);
        assertEq(address(config.hook), address(1));
        assertEq(kernel.currentNonce(), 3);
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
        assertEq(kernel.currentNonce(), 3);
        assertEq(
            MockSigner(address(permissionConfig.signer)).data(address(kernel)),
            abi.encodePacked(bytes32(bytes4(0xdeadbeef)), "signer")
        );
    }

    function testActionInstall() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockAction mockAction = new MockAction();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareRootUserOp(
            abi.encodeWithSelector(
                kernel.installModule.selector,
                7,
                address(mockAction),
                abi.encodePacked(MockAction.doSomething.selector, address(0))
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
                7,
                address(mockAction),
                abi.encodePacked(
                    MockAction.doSomething.selector, address(mockHook), abi.encodePacked(bytes1(0xff), "hookData")
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
                abi.encodePacked(address(0), abi.encode(abi.encodePacked("fallbackData"), abi.encodePacked("")))
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockFallback.data(address(kernel)), abi.encodePacked("fallbackData"));

        (IFallback fallbackHandler, IHook fallbackHook) = kernel.fallbackConfig();
        assertEq(address(fallbackHook), address(1));
        assertEq(address(fallbackHandler), address(mockFallback));

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
                    address(mockHook),
                    abi.encode(abi.encodePacked("fallbackData"), abi.encodePacked(bytes1(0xff), "hookData"))
                )
            ),
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockFallback.data(address(kernel)), abi.encodePacked("fallbackData"));

        assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));

        (IFallback fallbackHandler, IHook fallbackHook) = kernel.fallbackConfig();
        assertEq(address(fallbackHook), address(mockHook));
        assertEq(address(fallbackHandler), address(mockFallback));

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

    function testSignatureValidator() external {}

    function testSignaturePermission() external {}

    function testSignatureRoot() external {}

    function testEnablePermission() external {}

    function testEnableValidator() external {}

    // #2 permission standard
    // - root : validator, enable : permission
    // - root : validator, enable : permission
    // - root : permission, enable : permission
    // - root : permission, enable : validator
}
