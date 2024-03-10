pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "forge-std/Test.sol";
import "src/mock/MockValidator.sol";
import "src/mock/MockPolicy.sol";
import "src/mock/MockSigner.sol";
import "src/core/PermissionManager.sol";
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

contract KernelTest is Test {
    MockValidator validator;
    Kernel kernel;
    IEntryPoint entrypoint;
    MockCallee callee;

    modifier whenInitialized() {
        ValidationId vId = ValidatorLib.validatorToIdentifier(validator);
        kernel.initialize(vId, IHook(address(0)), hex"", hex"");
        _;
    }

    function setUp() public {
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        validator = new MockValidator();
        Kernel impl = new Kernel(entrypoint);
        callee = new MockCallee();
        kernel = Kernel(payable(address(new SimpleProxy(address(impl)))));
    }

    function testInitialize() external {
        ValidationId vId = ValidatorLib.validatorToIdentifier(validator);

        kernel.initialize(vId, IHook(address(0)), hex"", hex"");
        assertTrue(kernel.rootValidator() == vId);
        ValidationManager.ValidationConfig memory config;
        config = kernel.validatorConfig(vId);
        assertEq(config.nonce, 1);
        assertEq(address(config.hook), address(1));
        assertEq(validator.isInitialized(address(kernel)), true);
        assertEq(kernel.currentNonce(), 2);
    }

    // scenario
    function testValidateUserOpSuccess() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        uint256 count = validator.count();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), 0),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                kernel.execute.selector,
                ExecLib.encodeSimpleSingle(),
                ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
                ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        validator.sudoSetSuccess(true);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(validator.count(), count + 1);
    }

    function testValidateUserOpFail() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        uint256 count = validator.count();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), 0),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                kernel.execute.selector,
                ExecLib.encodeSimpleSingle(),
                ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
                ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        validator.sudoSetSuccess(false);
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(validator.count(), count);
    }

    function encodeEnableSignature(
        IHook hook,
        bytes memory validatorData,
        bytes memory hookData,
        bytes memory selectorData,
        bytes memory enableSig,
        bytes memory userOpSig
    ) internal view returns (bytes memory) {
        ///0x
        ///000000000001
        ///000005f5e100
        ///0000000000000000000000000000000000000000
        ///00000000000000000000000000000000000000000000000000000000000000a0
        ///00000000000000000000000000000000000000000000000000000000000000e0
        ///0000000000000000000000000000000000000000000000000000000000000120
        ///0000000000000000000000000000000000000000000000000000000000000160
        ///00000000000000000000000000000000000000000000000000000000000001a0
        ///0000000000000000000000000000000000000000000000000000000000000005
        ///68656c6c6f000000000000000000000000000000000000000000000000000000
        ///0000000000000000000000000000000000000000000000000000000000000005
        ///776f726c64000000000000000000000000000000000000000000000000000000
        ///0000000000000000000000000000000000000000000000000000000000000004
        ///e9ae5c5300000000000000000000000000000000000000000000000000000000
        ///0000000000000000000000000000000000000000000000000000000000000009
        ///656e61626c655369670000000000000000000000000000000000000000000000
        ///0000000000000000000000000000000000000000000000000000000000000009
        ///757365724f705369670000000000000000000000000000000000000000000000
        return abi.encodePacked(
            abi.encodePacked(hook), abi.encode(validatorData, hookData, selectorData, enableSig, userOpSig)
        );
    }

    function testValidateUserOpSuccessValidatorEnableMode() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        MockValidator newValidator = new MockValidator();
        uint256 count = validator.count();
        uint256 newCount = newValidator.count();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        uint192 encodedAsNonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(newValidator)),
            0
        );
        assertEq(kernel.currentNonce(), 2);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), encodedAsNonceKey),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                kernel.execute.selector,
                ExecLib.encodeSimpleSingle(),
                ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
                ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: encodeEnableSignature(
                IHook(address(0)),
                abi.encodePacked("hello"),
                abi.encodePacked("world"),
                abi.encodePacked(kernel.execute.selector),
                abi.encodePacked("enableSig"),
                abi.encodePacked("userOpSig")
                )
        });
        validator.sudoSetValidSig(abi.encodePacked("enableSig"));
        newValidator.sudoSetSuccess(true);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(validator.count(), count);
        assertEq(newValidator.count(), newCount + 1);
        ValidationManager.ValidationConfig memory config =
            kernel.validatorConfig(ValidatorLib.validatorToIdentifier(newValidator));
        assertEq(config.nonce, 2);
        assertEq(address(config.hook), address(1));
        assertEq(kernel.currentNonce(), 3);
    }

    function testValidateUserOpSuccessPermissionEnableMode() external whenInitialized {
        vm.deal(address(kernel), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        uint192 encodedAsNonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(bytes4(0xdeadbeef)), // permission id
            0
        );
        assertEq(kernel.currentNonce(), 2);
        bytes[] memory permissions = new bytes[](3);
        MockPolicy mockPolicy = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        permissions[0] = abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(mockPolicy))), hex"eeeeee"
        );
        permissions[1] = abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(mockPolicy2))), hex"cafecafe"
        );
        permissions[2] = abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(mockSigner))), hex"beefbeef"
        );
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), encodedAsNonceKey),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                kernel.execute.selector,
                ExecLib.encodeSimpleSingle(),
                ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
                ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: encodeEnableSignature(
                IHook(address(0)),
                abi.encode(permissions),
                abi.encodePacked("world"),
                abi.encodePacked(kernel.execute.selector),
                abi.encodePacked("enableSig"),
                abi.encodePacked(
                    bytes1(0),
                    bytes8(uint64(7)),
                    "policy1",
                    bytes1(uint8(1)),
                    bytes8(uint64(7)),
                    "policy2",
                    bytes1(0xff),
                    "userOpSig"
                )
                )
        });

        mockPolicy.sudoSetValidSig(address(kernel), bytes32(bytes4(0xdeadbeef)), "policy1");
        mockPolicy2.sudoSetValidSig(address(kernel), bytes32(bytes4(0xdeadbeef)), "policy2");
        validator.sudoSetValidSig(abi.encodePacked("enableSig"));
        mockSigner.sudoSetValidSig(address(kernel), bytes32(bytes4(0xdeadbeef)), abi.encodePacked("userOpSig"));
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(kernel.currentNonce(), 3);
    }

    // install action
    // - with hook
    // - without hook
    // install fallback
    // - with hook
    // - without hook
    // install executor
    // - with hook
    // - without hook
    // install Validator
    // #1 signature
    // eip 1271 replay issue
    // - validator
    // - permission
    // #2 permission standard
    // - root : validator, enable : permission
    // - root : validator, enable : permission
    // - root : permission, enable : permission
    // - root : permission, enable : validator
}
