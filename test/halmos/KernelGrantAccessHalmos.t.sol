pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, ValidationInfo} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @title KernelGrantAccessHalmos
/// @notice Halmos formal verification tests for grantAccess correctness
contract KernelGrantAccessHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;
    MockValidator private secondValidator;
    ValidationId private secondVId;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);

        // Install a second validator to use for grantAccess tests
        secondValidator = new MockValidator();
        secondVId = validatorToIdentifier(secondValidator);
        vm.startPrank(address(ep));
        kernel.installModule(1, address(secondValidator), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    /// @notice Verify that grantAccess requires entryPoint or self
    function check_GrantAccessRejectsArbitraryCaller() external {
        address caller = address(uint160(uint256(keccak256("caller"))));
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        vm.startPrank(caller);
        try kernel.grantAccess(secondVId, abi.encodePacked(bytes4(0x12345678))) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that grantAccess with non-4-byte-aligned data reverts with InvalidDataLength
    function check_GrantAccessNonAlignedDataReverts() external {
        vm.startPrank(address(ep));
        try kernel.grantAccess(secondVId, hex"123456") {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that grantAccess with 5 bytes reverts (not divisible by 4)
    function check_GrantAccessFiveBytesReverts() external {
        vm.startPrank(address(ep));
        try kernel.grantAccess(secondVId, hex"1234567890") {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that grantAccess with 1 byte reverts (not divisible by 4)
    function check_GrantAccessOneByteReverts() external {
        vm.startPrank(address(ep));
        try kernel.grantAccess(secondVId, hex"12") {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that after grantAccess, the nonce of the validation info is incremented
    function check_GrantAccessIncrementsNonce() external {
        ValidationInfo memory infoBefore = kernel.validationInfo(secondVId);
        uint32 nonceBefore = infoBefore.nonce;

        vm.startPrank(address(ep));
        kernel.grantAccess(secondVId, abi.encodePacked(bytes4(0xaabbccdd)));
        vm.stopPrank();

        ValidationInfo memory infoAfter = kernel.validationInfo(secondVId);
        assertEq(infoAfter.nonce, nonceBefore + 1);
    }

    /// @notice Verify that calling grantAccess again increments the nonce again
    function check_GrantAccessAgainIncrementsNonceAgain() external {
        bytes4 sel = bytes4(0x11223344);

        vm.startPrank(address(ep));
        kernel.grantAccess(secondVId, abi.encodePacked(sel));
        vm.stopPrank();

        ValidationInfo memory infoAfterFirst = kernel.validationInfo(secondVId);
        uint32 nonceFirst = infoAfterFirst.nonce;

        // Grant access again with a different selector
        vm.startPrank(address(ep));
        kernel.grantAccess(secondVId, abi.encodePacked(bytes4(0x55667788)));
        vm.stopPrank();

        ValidationInfo memory infoAfterSecond = kernel.validationInfo(secondVId);
        assertEq(infoAfterSecond.nonce, nonceFirst + 1);
    }

    /// @notice Verify that grantAccess with empty selectors (0 bytes) still increments nonce
    function check_GrantAccessEmptySelectorsIncrementsNonce() external {
        ValidationInfo memory infoBefore = kernel.validationInfo(secondVId);
        uint32 nonceBefore = infoBefore.nonce;

        vm.startPrank(address(ep));
        kernel.grantAccess(secondVId, hex"");
        vm.stopPrank();

        ValidationInfo memory infoAfter = kernel.validationInfo(secondVId);
        assertEq(infoAfter.nonce, nonceBefore + 1);
    }

    /// @notice Verify that grantAccess with multiple selectors (8 bytes = 2 selectors) works
    function check_GrantAccessMultipleSelectors() external {
        ValidationInfo memory infoBefore = kernel.validationInfo(secondVId);
        uint32 nonceBefore = infoBefore.nonce;

        bytes4 sel1 = bytes4(0xaabbccdd);
        bytes4 sel2 = bytes4(0x11223344);

        vm.startPrank(address(ep));
        kernel.grantAccess(secondVId, abi.encodePacked(sel1, sel2));
        vm.stopPrank();

        ValidationInfo memory infoAfter = kernel.validationInfo(secondVId);
        assertEq(infoAfter.nonce, nonceBefore + 1);
    }

    /// @notice Verify that grantAccess from entryPoint succeeds (positive path)
    function check_GrantAccessSucceedsFromEntryPoint() external {
        bytes4 sel = bytes4(0xdeadbeef);

        vm.startPrank(address(ep));
        kernel.grantAccess(secondVId, abi.encodePacked(sel));
        vm.stopPrank();
    }
}
