pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";
import {InvalidValidationType, InvalidVid} from "src/types/Error.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

contract KernelSignatureHalmos is SymTest, Test {
    Kernel private kernel;
    MockValidator private rootValidator;

    function setUp() external {
        IEntryPoint ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
    }

    function checkRootSignatureValid() external {
        bytes32 hash = bytes32(svm.createBytes(32, "hash"));
        bytes memory sig = svm.createBytes(65, "sig");
        rootValidator.sudoSetValidSig(sig);
        bytes4 ret = kernel.isValidSignature(hash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function checkRootSignatureInvalid() external {
        bytes32 hash = bytes32(svm.createBytes(32, "hash"));
        bytes memory sig = svm.createBytes(65, "sig");
        bytes4 ret = kernel.isValidSignature(hash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function checkInvalidValidationTypeReverts() external {
        bytes32 hash = bytes32(svm.createBytes(32, "hash"));
        bytes memory sig = svm.createBytes(65, "sig");
        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(hash, abi.encodePacked(bytes1(0), bytes1(0x03), sig));
    }

    function checkValidatorNotInstalledReverts() external {
        MockValidator validator = new MockValidator();
        bytes32 hash = bytes32(svm.createBytes(32, "hash"));
        bytes memory sig = svm.createBytes(65, "sig");
        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, validatorToIdentifier(validator)));
        kernel.isValidSignature(hash, abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(validator)), sig));
    }
}
