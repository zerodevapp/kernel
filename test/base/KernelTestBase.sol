// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/factory/KernelFactory.sol";
import "src/factory/FactoryStaker.sol";
import "solady_test/utils/TestPlus.sol";
import "forge-std/Test.sol";
import "../mock/MockCallee.sol";
import "../mock/MockValidator.sol";
import "../mock/MockPolicy.sol";
import "../mock/MockSigner.sol";
import "../mock/MockAction.sol";
import "../mock/MockHook.sol";
import "../mock/MockExecutor.sol";
import "../mock/MockFallback.sol";
import "../mock/MockERC20.sol";
import "../mock/MockERC721.sol";
import "../mock/MockERC1155.sol";
import "src/core/ValidationManager.sol";
import "./erc4337Util.sol";
import "src/types/Types.sol";
import "src/types/Structs.sol";
import "solady/accounts/LibERC7579.sol";

abstract contract KernelTestBase is TestPlus, Test {
    address stakerOwner;
    Kernel kernel;
    KernelFactory factory;
    FactoryStaker staker;
    IEntryPoint entrypoint;
    ValidationId rootValidation;
    bytes[] initConfig;

    struct RootValidationConfig {
        IHook hook;
        bytes validatorData;
        bytes hookData;
    }

    RootValidationConfig rootValidationConfig;
    MockValidator mockValidator;
    MockCallee callee;
    MockHook mockHook;
    MockFallback mockFallback;
    MockExecutor mockExecutor;
    MockERC20 mockERC20;
    MockERC721 mockERC721;
    MockERC1155 mockERC1155;

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
        assertEq(ValidationId.unwrap(kernel.rootValidator()), ValidationId.unwrap(rootValidation));
        _;
    }

    modifier whenValidatorEnabled(bool useFallback, bool isExecutor) {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_VALIDATOR,
            useFallback,
            isExecutor,
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        _;
    }

    modifier whenPermissionEnabled(bool useFallback, bool isExecutor) {
        _;
    }

    function needEnable(ValidationType vType) internal view returns (bool) {
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            if (
                address(kernel.validationConfig(ValidatorLib.validatorToIdentifier(enabledValidator)).hook)
                    == address(0)
            ) {
                return true;
            }
            return false;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            return address(kernel.validationConfig(ValidatorLib.permissionToIdentifier(enabledPermission)).hook)
                == address(0);
        } else if (vType == VALIDATION_TYPE_ROOT) {
            return false;
        } else {
            revert("Invalid validation type");
        }
    }

    function encodeNonce(ValidationType vType, bool enable) internal view returns (uint256 nonce) {
        uint192 nonceKey = 0;
        if (vType == VALIDATION_TYPE_ROOT) {
            nonceKey = 0;
        } else if (vType == VALIDATION_TYPE_VALIDATOR) {
            ValidationMode mode = VALIDATION_MODE_DEFAULT;
            if (enable) {
                mode = VALIDATION_MODE_ENABLE;
            }
            nonceKey = ValidatorLib.encodeAsNonceKey(
                ValidationMode.unwrap(mode),
                ValidationType.unwrap(vType),
                bytes20(address(enabledValidator)),
                0 // parallel key
            );
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            ValidationMode mode = VALIDATION_MODE_DEFAULT;
            if (enable) {
                mode = VALIDATION_MODE_ENABLE;
            }
            nonceKey = ValidatorLib.encodeAsNonceKey(
                ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
                ValidationType.unwrap(vType),
                bytes20(PermissionId.unwrap(enabledPermission)), // permission id
                0
            );
        } else {
            revert("Invalid validation type");
        }
        return entrypoint.getNonce(address(kernel), nonceKey);
    }

    function getEnableDigest(
        ValidationType vType,
        bool overrideValidation,
        bytes memory selectorData,
        bool isReplayable
    ) internal view returns (bytes32) {
        uint32 nonce = kernel.currentNonce();
        if (overrideValidation) {
            nonce = nonce + 1;
        }
        ValidationId vId;
        IHook hook;
        bytes memory validatorData;
        bytes memory hookData;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            vId = ValidatorLib.validatorToIdentifier(enabledValidator);
            hook = validationConfig.hook;
            validatorData = validationConfig.validatorData;
            hookData = validationConfig.hookData;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            vId = ValidatorLib.permissionToIdentifier(enabledPermission);
            hook = permissionConfig.hook;
            validatorData = encodePermissionsEnableData();
            hookData = permissionConfig.hookData;
        } else {
            revert("Invalid validation type");
        }

        bytes32 hash = keccak256(
            abi.encode(
                keccak256(
                    "Enable(bytes21 validationId,uint32 nonce,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                ),
                ValidationId.unwrap(vId),
                uint256(nonce),
                hook,
                keccak256(validatorData),
                keccak256(abi.encodePacked(hex"ff", hookData)),
                keccak256(selectorData)
            )
        );

        bytes32 digest;
        if (isReplayable) {
            digest = chainAgnosticHashTypedData(address(kernel), "Kernel", "0.3.3", hash);
        } else {
            digest =
                keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.3", address(kernel)), hash));
        }

        return digest;
    }

    function encodeSelectorData(bool isFallback, bool isExecutor) internal view returns (bytes memory) {
        if (isFallback && isExecutor) {
            return abi.encodePacked(
                MockFallback.setData.selector,
                address(mockFallback),
                address(1),
                abi.encode(abi.encodePacked(hex"00", "MockFallbackInit"), hex"", abi.encodePacked(address(0))) // TODO add executor hook test
            );
        } else if (isFallback) {
            return abi.encodePacked(
                MockFallback.setData.selector,
                address(mockFallback),
                address(1),
                abi.encode(abi.encodePacked(hex"00", "MockFallbackInit"), hex"")
            );
        } else if (!isFallback && !isExecutor) {
            return abi.encodePacked(Kernel.execute.selector);
        } else {
            revert("Invalid selector data");
        }
    }

    function getValidationId(ValidationType vType) internal view returns (ValidationId) {
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            return ValidatorLib.validatorToIdentifier(enabledValidator);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            return ValidatorLib.permissionToIdentifier(enabledPermission);
        } else {
            revert("Invalid validation type");
        }
    }

    function getEnableSignature(
        ValidationType vType,
        bytes32 digest,
        bytes memory selectorData,
        PackedUserOperation memory op,
        bool successEnable,
        bool successUserOp,
        bool isReplayable
    ) internal returns (bytes memory) {
        bytes memory enableSig = _rootSignDigest(digest, successEnable);
        bytes memory userOpSig = _signUserOp(vType, op, successUserOp, isReplayable);
        IHook hook;
        bytes memory validatorData;
        bytes memory hookData;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            hook = validationConfig.hook;
            validatorData = validationConfig.validatorData;
            hookData = validationConfig.hookData;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            hook = permissionConfig.hook;
            validatorData = encodePermissionsEnableData();
            hookData = permissionConfig.hookData;
        } else {
            revert("Invalid validation type");
        }
        return encodeEnableSignature(
            hook, validatorData, abi.encodePacked(hex"ff", hookData), selectorData, enableSig, userOpSig, isReplayable
        );
    }

    function _prepareUserOp(
        ValidationType vType,
        bool isFallback,
        bool isExecutor,
        bytes memory callData,
        bool successEnable,
        bool successUserOp,
        bool isReplayable
    ) internal returns (PackedUserOperation memory op) {
        if (isFallback && isExecutor) {
            mockFallback.setExecutorMode(true);
        }
        bool enable = needEnable(vType);
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(vType, enable),
            initCode: address(kernel).code.length == 0
                ? abi.encodePacked(
                    address(staker), abi.encodeWithSelector(staker.deployWithFactory.selector, factory, initData(), bytes32(0))
                )
                : abi.encodePacked(hex""),
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"", // TODO have paymaster test cases
            signature: hex""
        });
        if (enable) {
            bytes memory selectorData = encodeSelectorData(isFallback, isExecutor);
            bytes32 digest = getEnableDigest(vType, false, selectorData, isReplayable);
            op.signature =
                getEnableSignature(vType, digest, selectorData, op, successEnable, successUserOp, isReplayable);
        } else {
            op.signature = _signUserOp(vType, op, successUserOp, isReplayable);
        }
        if (isReplayable) {
            op.signature = abi.encodePacked(MAGIC_VALUE_SIG_REPLAYABLE, op.signature);
        }
    }

    function setUp() public virtual {
        enabledPermission = PermissionId.wrap(bytes4(0xdeadbeef));
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entrypoint);
        factory = new KernelFactory(address(impl));
        callee = new MockCallee();
        mockHook = new MockHook();
        mockFallback = new MockFallback();
        mockExecutor = new MockExecutor();
        mockERC20 = new MockERC20();
        mockERC721 = new MockERC721();
        mockERC1155 = new MockERC1155();
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
        ops[0] = _prepareUserOp(VALIDATION_TYPE_ROOT, false, false, hex"", true, true, false);
        // _prepareRootUserOp(hex"", true);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function testInitConfig() external {
        bytes[] memory configs = new bytes[](1);
        MockValidator mv = new MockValidator();
        configs[0] = abi.encodeWithSelector(
            Kernel.installModule.selector, 1, address(mv), abi.encodePacked(address(0), abi.encode(hex"", hex"", hex""))
        );
        initConfig = configs;
        kernel = Kernel(payable(factory.getAddress(initData(), bytes32(0))));
        address deployed = factory.createAccount(initData(), bytes32(0));
        assertEq(deployed, address(kernel));
        assertEq(kernel.currentNonce(), 1);
        assertEq(ValidationId.unwrap(kernel.rootValidator()), ValidationId.unwrap(rootValidation));
        ValidationManager.ValidationConfig memory config =
            kernel.validationConfig(ValidatorLib.validatorToIdentifier(mv));
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
    }

    function test_receive() external whenInitialized {
        vm.expectEmit(false, false, false, true, address(kernel));
        emit Kernel.Received(address(this), 1);
        (bool success,) = address(kernel).call{value: 1}(hex"");
        require(success, "eth transfer failed");

        mockERC721.mint(address(kernel), 100);
        mockERC721.safeMint(address(kernel), 999);

        mockERC1155.mint(address(kernel), 100, 1, hex"");
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 200;
        ids[1] = 201;
        amounts[0] = 1;
        amounts[1] = 1000;
        mockERC1155.batchMint(address(kernel), ids, amounts, hex"");
    }

    function initData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            Kernel.initialize.selector,
            rootValidation,
            rootValidationConfig.hook,
            rootValidationConfig.validatorData,
            rootValidationConfig.hookData,
            initConfig
        );
    }

    function encodeEnableSignature(
        IHook hook,
        bytes memory validatorData,
        bytes memory hookData,
        bytes memory selectorData,
        bytes memory enableSig,
        bytes memory userOpSig,
        bool isReplayable
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encodePacked(hook), abi.encode(validatorData, hookData, selectorData, enableSig, userOpSig)
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

    function _rootSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        if (success) {
            data = "enableSig";
            mockValidator.sudoSetValidSig(data);
        } else {
            data = "failEnableSig";
        }
    }

    function _signUserOp(ValidationType vType, PackedUserOperation memory op, bool success, bool isReplayable)
        internal
        virtual
        returns (bytes memory sig)
    {
        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        if (isReplayable) {
            userOpHash = kernel.replayableUserOpHash(op, address(entrypoint));
        }
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            sig = _validatorSignUserOp(op, userOpHash, success);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            sig = _permissionSignUserOp(op, userOpHash, success);
        } else if (vType == VALIDATION_TYPE_ROOT) {
            sig = _rootSignUserOp(op, userOpHash, success);
        } else {
            revert("Invalid validation type");
        }
    }

    function _rootSignUserOp(PackedUserOperation memory op, bytes32 userOpHash, bool success)
        internal
        virtual
        returns (bytes memory)
    {
        mockValidator.sudoSetSuccess(success);
        return success ? abi.encodePacked("success") : abi.encodePacked("failure");
    }

    function _validatorSignUserOp(PackedUserOperation memory, bytes32 userOpHash, bool success)
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

    function _permissionSignUserOp(PackedUserOperation memory op, bytes32 userOpHash, bool success)
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
            address(kernel),
            bytes32(PermissionId.unwrap(enabledPermission)),
            success ? abi.encodePacked("userOpSig") : abi.encodePacked("NO")
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
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), success
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

    //  --- Root validator cases, no need to enable ---
    function testRootValidateUser(bool success) external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)),
            true,
            success,
            false
        );
        if (!success) {
            vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        }
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        if (success) {
            _rootValidatorSuccessCheck();
        }
    }

    function testRootValidateUserReplayable(bool success) external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)),
            true,
            success,
            true
        );
        if (!success) {
            vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        }
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        if (success) {
            _rootValidatorSuccessCheck();
        }
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

    function encodeExecute(address _to, uint256 _amount, bytes memory _data) internal view returns (bytes memory) {
        return abi.encodeWithSelector(kernel.execute.selector, bytes32(0), ExecLib.encodeSingle(_to, _amount, _data));
    }

    function encodeBatchExecute(Execution[] memory execs) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            kernel.execute.selector,
            LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encode(execs)
        );
    }

    function testInvalidateNonce(uint32 nonce) external whenInitialized {
        uint32 kernelNonce = kernel.currentNonce();
        bytes memory errorMsg;
        if (nonce < kernelNonce) {
            errorMsg = abi.encodeWithSelector(ValidationManager.InvalidNonce.selector);
        } else if (nonce > kernelNonce + MAX_NONCE_INCREMENT_SIZE) {
            errorMsg = abi.encodeWithSelector(ValidationManager.NonceInvalidationError.selector);
        }
        if (errorMsg.length > 0) {
            vm.expectRevert(errorMsg);
        }
        vm.prank(address(kernel));
        kernel.invalidateNonce(nonce);
        if (errorMsg.length > 0) {
            assertEq(kernel.currentNonce(), kernelNonce);
        } else {
            assertEq(kernel.currentNonce(), nonce);
            assertEq(kernel.validNonceFrom(), nonce);
        }
    }

    function testValidateUserOpWithEnable(
        ValidationType vType,
        bool useFallback,
        bool isExecutor,
        bool enableSuccess,
        bool userOpSuccess,
        bool replayable
    ) external whenInitialized {
        vm.assume(vType == VALIDATION_TYPE_VALIDATOR || vType == VALIDATION_TYPE_PERMISSION);
        if (useFallback == false && isExecutor == true) {
            isExecutor = false;
        }
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            vType,
            useFallback,
            isExecutor,
            useFallback
                ? abi.encodeWithSelector(MockFallback.setData.selector, 123456)
                : encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)),
            enableSuccess,
            userOpSuccess,
            replayable
        );
        if (!enableSuccess) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodePacked(ValidationManager.EnableNotApproved.selector)
                )
            );
        } else if (!userOpSuccess) {
            vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        }
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        if (enableSuccess && userOpSuccess) {
            ValidationManager.ValidationConfig memory config = kernel.validationConfig(getValidationId(vType));
            assertEq(config.nonce, 1);
            assertEq(address(config.hook), address(1));
            assertEq(kernel.currentNonce(), 1);
            if (vType == VALIDATION_TYPE_PERMISSION) {
                ValidationManager.PermissionConfig memory pConfig = kernel.permissionConfig(enabledPermission);
                pConfig.signer = permissionConfig.signer;
            }
            if (useFallback) {
                assertEq(kernel.isAllowedSelector(getValidationId(vType), MockFallback.setData.selector), true);
                assertEq(mockFallback.valueStored(), 123456);
                Callee callee1 = mockFallback.callee();
                if (isExecutor) {
                    assertEq(callee1.lastCaller(), address(kernel));
                } else {
                    assertEq(callee1.lastCaller(), address(0));
                }
            } else {
                assertEq(kernel.isAllowedSelector(getValidationId(vType), Kernel.execute.selector), true);
                assertEq(callee.value(), 123);
            }
        }
    }

    function encodePermissionsEnableData() internal view returns (bytes memory) {
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

    enum HookInfo {
        NoHook,
        DefaultHook,
        WithHook
    }

    function _installValidator(IValidator validator) internal {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                1,
                address(validator),
                abi.encodePacked(
                    address(0), // Hook
                    abi.encode(
                        hex"", // validator data
                        hex"", // hook data
                        hex"" // selector data
                    )
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function _uninstallValidator(IValidator validator) internal {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(kernel.uninstallModule.selector, 1, address(validator), hex""),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function testValidatorInstall() external whenInitialized {
        MockValidator mv = new MockValidator();
        _installValidator(mv);
        ValidationManager.ValidationConfig memory config =
            kernel.validationConfig(ValidatorLib.validatorToIdentifier(mv));
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
        _uninstallValidator(mv);
        config = kernel.validationConfig(ValidatorLib.validatorToIdentifier(mv));
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(0));
        _installValidator(mv);
        config = kernel.validationConfig(ValidatorLib.validatorToIdentifier(mv));
        assertEq(config.nonce, 2);
        assertEq(address(config.hook), address(1));
    }

    function _installAction(HookInfo withHook) internal {
        vm.deal(address(kernel), 1e18);
        MockAction mockAction = new MockAction();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                3,
                address(mockAction),
                abi.encodePacked(
                    MockAction.doSomething.selector,
                    withHook == HookInfo.WithHook
                        ? address(mockHook)
                        : withHook == HookInfo.NoHook ? address(1) : address(0),
                    withHook == HookInfo.WithHook
                        ? abi.encode(hex"ff", abi.encodePacked(bytes1(0xff), "hookData"))
                        : abi.encode(hex"ff", hex"")
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function testActionInstall(uint8 hookUint) external whenInitialized {
        vm.assume(uint8(hookUint) < 3);
        HookInfo withHook = HookInfo(hookUint);
        _installAction(withHook);
        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockAction.doSomething.selector);
        assertEq(
            address(config.hook),
            withHook == HookInfo.WithHook
                ? address(mockHook)
                : withHook == HookInfo.NoHook ? address(1) : address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF)
        );
        if (withHook != HookInfo.DefaultHook) {
            vm.expectEmit(address(kernel));
            emit MockAction.MockActionEvent(address(kernel));
            MockAction(address(kernel)).doSomething();
        } else {
            vm.expectRevert();
            MockAction(address(kernel)).doSomething();
            PackedUserOperation memory op = _prepareUserOp(
                VALIDATION_TYPE_ROOT,
                false,
                false,
                abi.encodeWithSelector(MockAction.doSomething.selector),
                true,
                true,
                false
            );
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            vm.expectEmit(address(kernel));
            emit MockAction.MockActionEvent(address(kernel));
            entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        }

        if (withHook == HookInfo.WithHook) {
            assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));
            assertEq(
                mockHook.preHookData(address(kernel)), abi.encodePacked(address(this), MockAction.doSomething.selector)
            );
            assertEq(mockHook.postHookData(address(kernel)), abi.encodePacked("hookData"));
        }
    }

    function testActionUninstall(uint8 hookUint) external whenInitialized {
        vm.assume(uint8(hookUint) < 3);
        HookInfo withHook = HookInfo(hookUint);
        _installAction(withHook);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.uninstallModule.selector,
                3,
                address(mockFallback),
                abi.encodePacked(MockAction.doSomething.selector)
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockAction.doSomething.selector);
        assertEq(address(config.hook), address(0));
        assertEq(address(config.target), address(0));
    }

    function _installFallback(HookInfo withHook) internal {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                3,
                address(mockFallback),
                abi.encodePacked(
                    MockFallback.fallbackFunction.selector,
                    withHook == HookInfo.WithHook
                        ? address(mockHook)
                        : withHook == HookInfo.NoHook ? address(1) : address(0),
                    withHook == HookInfo.WithHook
                        ? abi.encode(abi.encodePacked(hex"00", "fallbackData"), abi.encodePacked(bytes1(0xff), "hookData"))
                        : abi.encode(abi.encodePacked(hex"00", "fallbackData"), abi.encodePacked(""))
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function testFallbackInstall(uint8 hookUint) external whenInitialized {
        vm.assume(uint8(hookUint) < 3);
        HookInfo withHook = HookInfo(hookUint);
        _installFallback(withHook);
        assertEq(mockFallback.data(address(kernel)), abi.encodePacked("fallbackData"));

        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(
            address(config.hook),
            withHook == HookInfo.WithHook
                ? address(mockHook)
                : withHook == HookInfo.NoHook ? address(1) : address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF)
        );
        assertEq(address(config.target), address(mockFallback));
        if (withHook != HookInfo.DefaultHook) {
            (bool success, bytes memory result) =
                address(kernel).call(abi.encodeWithSelector(MockFallback.fallbackFunction.selector, uint256(10)));
            assertTrue(success);
            (uint256 res) = abi.decode(result, (uint256));
            assertEq(res, 100);
        } else {
            (bool success, bytes memory result) =
                address(kernel).call(abi.encodeWithSelector(MockFallback.fallbackFunction.selector, uint256(10)));
            assertFalse(success);
            PackedUserOperation memory op = _prepareUserOp(
                VALIDATION_TYPE_ROOT,
                false,
                false,
                abi.encodeWithSelector(MockFallback.fallbackFunction.selector, uint256(10)),
                true,
                true,
                false
            );
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        }
        if (withHook == HookInfo.WithHook) {
            assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));
            assertEq(
                mockHook.preHookData(address(kernel)),
                abi.encodePacked(address(this), MockFallback.fallbackFunction.selector, uint256(10))
            );
            assertEq(mockHook.postHookData(address(kernel)), abi.encodePacked("hookData"));
        }
    }

    function testFallbackUninstall(uint8 hookUint) external whenInitialized {
        vm.assume(uint8(hookUint) < 3);
        HookInfo withHook = HookInfo(hookUint);
        _installFallback(withHook);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.uninstallModule.selector,
                3,
                address(mockFallback),
                abi.encodePacked(MockFallback.fallbackFunction.selector)
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        SelectorManager.SelectorConfig memory config = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(config.hook), address(0));
        assertEq(address(config.target), address(0));
    }

    function _installExecutor(bool withHook) internal {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                2,
                address(mockExecutor),
                abi.encodePacked(
                    withHook ? address(mockHook) : address(0),
                    withHook
                        ? abi.encode(abi.encodePacked("executorData"), abi.encodePacked(bytes1(0xff), "hookData"))
                        : abi.encode(abi.encodePacked("executorData"), abi.encodePacked(""))
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function testExecute(CallType callType, ExecType execType, bool shouldFail) external whenInitialized {
        unchecked {
            vm.assume(uint8(CallType.unwrap(callType)) + 1 < 3); //only call/batch/delegatecall
            vm.assume(uint8(ExecType.unwrap(execType)) < 2);
        }
        vm.startPrank(address(entrypoint));
        ExecMode code = ExecLib.encode(callType, execType, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00));
        if (callType == CALLTYPE_BATCH) {
            Execution[] memory execs = new Execution[](1);
            execs[0] = Execution({
                target: address(callee),
                value: 0,
                callData: abi.encodeWithSelector(MockCallee.emitEvent.selector, shouldFail)
            });
            bytes memory data = ExecLib.encodeBatch(execs);
            if (execType == EXECTYPE_DEFAULT && shouldFail) {
                vm.expectRevert();
            }
            kernel.execute(code, data);
        } else if (callType == CALLTYPE_SINGLE) {
            if (execType == EXECTYPE_DEFAULT && shouldFail) {
                vm.expectRevert();
            }
            kernel.execute(
                code,
                abi.encodePacked(
                    address(callee), uint256(0), abi.encodeWithSelector(MockCallee.emitEvent.selector, shouldFail)
                )
            );
        } else {
            if (execType == EXECTYPE_DEFAULT && shouldFail) {
                vm.expectRevert();
            }
            kernel.execute(
                code,
                abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.emitEvent.selector, shouldFail))
            );
        }
    }

    function testExecutorInstall(bool withHook) external whenInitialized {
        _installExecutor(withHook);
        assertEq(mockExecutor.data(address(kernel)), abi.encodePacked("executorData"));
        ExecutorManager.ExecutorConfig memory config = kernel.executorConfig(mockExecutor);
        assertEq(address(config.hook), withHook ? address(mockHook) : address(1));

        ExecMode mode = ExecMode.wrap(bytes32(0));
        bytes memory data =
            ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(MockCallee.setValue.selector, 123));
        mockExecutor.sudoDoExec(IERC7579Account(kernel), mode, data);
        assertEq(callee.value(), 123);
        if (withHook) {
            assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));
            assertEq(mockHook.data(address(kernel)), abi.encodePacked("hookData"));
        }
    }

    function testExecutorUninstall(bool withHook) external whenInitialized {
        _installExecutor(withHook);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(kernel.uninstallModule.selector, 2, address(mockExecutor), hex""),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        ExecutorManager.ExecutorConfig memory config = kernel.executorConfig(mockExecutor);
        assertEq(address(config.hook), address(0));
        vm.expectRevert(abi.encodeWithSelector(Kernel.InvalidExecutor.selector));
        vm.startPrank(address(mockExecutor));
        kernel.executeFromExecutor(
            ExecMode.wrap(bytes32(0)),
            ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(MockCallee.setValue.selector, 123))
        );
        vm.stopPrank();
    }

    function testSignatureRoot(bytes32 hash) external whenInitialized {
        bytes32 wrappedHash = keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.3", address(kernel)), wrappedHash)
        );
        bytes memory sig = _rootSignDigest(digest, true);
        sig = abi.encodePacked(hex"00", sig);
        bytes4 res = kernel.isValidSignature(hash, sig);
        assertEq(res, bytes4(0x1626ba7e));
    }

    function testSignatureValidator(bytes32 hash) external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_VALIDATOR,
            false,
            false,
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        ValidationManager.ValidationConfig memory config =
            kernel.validationConfig(ValidatorLib.validatorToIdentifier(enabledValidator));
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
        assertEq(kernel.currentNonce(), 1);

        bytes32 wrappedHash = keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.3", address(kernel)), wrappedHash)
        );
        bytes memory sig = _validatorSignDigest(digest, true);
        sig = abi.encodePacked(hex"01", address(enabledValidator), sig);
        bytes4 res = kernel.isValidSignature(hash, sig);
        assertEq(res, bytes4(0x1626ba7e));
    }

    function testSignaturePermission(bytes32 hash) external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_PERMISSION,
            false,
            false,
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123)),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(kernel.currentNonce(), 1);
        assertEq(
            MockSigner(address(permissionConfig.signer)).data(address(kernel)),
            abi.encodePacked(bytes32(bytes4(0xdeadbeef)), "signer")
        );
        bytes32 wrappedHash = keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), hash));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.3", address(kernel)), wrappedHash)
        );
        bytes memory sig = _permissionSignDigest(digest, true);
        sig = abi.encodePacked(hex"02", PermissionId.unwrap(enabledPermission), hex"ff", sig);
        bytes4 res = kernel.isValidSignature(hash, sig);
        assertEq(res, bytes4(0x1626ba7e));
    }

    function testExecuteBatch(uint8 length) external whenInitialized {
        vm.startPrank(address(entrypoint));
        ExecMode mode = ExecMode.wrap(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)));
        Execution[] memory execs = new Execution[](length);
        uint256 sum = 0;
        for (uint256 i = 0; i < length; i++) {
            uint256 random = _random() % 10000;
            sum += random;
            execs[i] = Execution({
                target: address(callee),
                value: 0,
                callData: abi.encodeWithSelector(MockCallee.addValue.selector, random)
            });
        }
        bytes memory data = abi.encode(execs);
        kernel.execute(mode, data);
        assertEq(callee.value(), sum);
    }

    /// @dev Returns the EIP-712 domain separator.
    function buildChainAgnosticDomainSeparator(address addr, string memory name, string memory version)
        private
        view
        returns (bytes32 separator)
    {
        // We will use `separator` to store the name hash to save a bit of gas.
        bytes32 versionHash;
        separator = keccak256(bytes(name));
        versionHash = keccak256(bytes(version));
        bytes32 typeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, typeHash)
            mstore(add(m, 0x20), separator) // Name hash.
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), 0x00) //  NOTE : user chainId == 0 as eip 7702 did
            mstore(add(m, 0x80), addr)
            separator := keccak256(m, 0xa0)
        }
    }

    function chainAgnosticHashTypedData(address addr, string memory name, string memory version, bytes32 structHash)
        internal
        view
        virtual
        returns (bytes32 digest)
    {
        // we don't do cache stuff here
        digest = buildChainAgnosticDomainSeparator(addr, name, version);
        /// @solidity memory-safe-assembly
        assembly {
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }
    }
}
