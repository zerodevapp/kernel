pragma solidity ^0.8.0;

import {ECDSAValidator} from "../src/validator/ECDSAValidator.sol";
import {MockCallee, KernelTestBase} from "../src/sdk/KernelTestBase.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {PackedUserOperation} from "../src/interfaces/PackedUserOperation.sol";
import {ValidatorLib} from "../src/utils/ValidationTypeLib.sol";
import {ExecLib} from "../src/utils/ExecLib.sol";
import {IHook} from "../src/interfaces/IERC7579Modules.sol";
import {ValidatorLib, ValidationId, ValidationMode, ValidationType} from "../src/utils/ValidationTypeLib.sol";
import {VALIDATION_MODE_ENABLE, VALIDATION_TYPE_VALIDATOR} from "../src/types/Constants.sol";

import "forge-std/console.sol";

contract ECDSAValidatorTest is KernelTestBase {
    ECDSAValidator ecdsaValidator;
    address owner;
    uint256 ownerKey;

    function _setRootValidationConfig() internal override {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        ecdsaValidator = new ECDSAValidator();
        rootValidation = ValidatorLib.validatorToIdentifier(ecdsaValidator);
        rootValidationConfig =
            RootValidationConfig({hook: IHook(address(0)), hookData: hex"", validatorData: abi.encodePacked(owner)});
    }

    function _rootSignDigest(bytes32 digest, bool success) internal view override returns (bytes memory data) {
        unchecked {
            if (!success) {
                digest = bytes32(uint256(digest) - 1);
            }
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(digest));
        bytes memory sig = abi.encodePacked(r, s, v);
        return sig;
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success)
        internal
        view
        override
        returns (bytes memory)
    {
        bytes32 hash = entrypoint.getUserOpHash(op);
        return _rootSignDigest(hash, success);
    }

    function testExternalInteraction() external whenInitialized {
        vm.startPrank(owner);
        kernel.execute(
            ExecLib.encodeSimpleSingle(),
            ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(MockCallee.setValue.selector, 123))
        );
        vm.stopPrank();
    }

    function testEnableMalicious() external whenInitialized {
        vm.startPrank(owner);
        vm.deal(address(kernel), 1e18);
        kernel.invalidateNonce(2);
        vm.stopPrank();
        (address hacker, uint256 hackerKey) = makeAddrAndKey("Hacker");
        ownerKey = hackerKey;
        enabledValidator = ecdsaValidator;
        validationConfig.validatorData = abi.encodePacked(hacker);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareMaliciousEnableUserOp(
            encodeExecute(address(callee), 0, abi.encodeWithSelector(callee.setValue.selector, 123))
        );
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function _prepareMaliciousEnableUserOp(bytes memory callData) internal returns (PackedUserOperation memory op) {
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
            accountGasLimits: bytes32(abi.encodePacked(uint128(2000000), uint128(2000000))),
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
            _rootSignUserOp(op, true)
        );
    }
}
