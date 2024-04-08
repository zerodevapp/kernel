pragma solidity ^0.8.0;

import {MockCallee, KernelTestBase} from "src/sdk/testBase/KernelTestBase.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {ValidatorLib} from "src/utils/ValidationTypeLib.sol";
import {ExecLib} from "src/utils/ExecLib.sol";
import {IHook} from "src/interfaces/IERC7579Modules.sol";

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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(digest));
        if (!success) {
            r = bytes32(uint256(r) - 1);
        }
        return abi.encodePacked(r, s, v);
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
}
