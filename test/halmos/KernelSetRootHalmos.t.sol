pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";

/// @title KernelSetRootHalmos
/// @notice Halmos formal verification tests for setRoot access control
contract KernelSetRootHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;
    MockValidator private secondValidator;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);

        // Install a second validator so we can test setRoot to it
        secondValidator = new MockValidator();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(secondValidator), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    /// @notice Verify that an arbitrary non-EP, non-self caller cannot call setRoot(ValidationId)
    function check_SetRootVIdRejectsArbitraryCaller() external {
        address caller = address(uint160(uint256(keccak256("caller"))));
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        ValidationId vId = validatorToIdentifier(secondValidator);

        vm.startPrank(caller);
        try kernel.setRoot(vId) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that entryPoint CAN call setRoot(ValidationId)
    function check_SetRootVIdSucceedsFromEntryPoint() external {
        ValidationId vId = validatorToIdentifier(secondValidator);

        vm.startPrank(address(ep));
        kernel.setRoot(vId);
        vm.stopPrank();

        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(vId));
    }

    /// @notice Verify that self (kernel) CAN call setRoot(ValidationId) via execute
    function check_SetRootVIdSucceedsFromSelf() external {
        ValidationId vId = validatorToIdentifier(secondValidator);

        vm.startPrank(address(ep));
        kernel.execute(
            bytes32(0),
            abi.encodePacked(
                address(kernel), uint256(0), abi.encodeWithSignature("setRoot(bytes21)", ValidationId.unwrap(vId))
            )
        );
        vm.stopPrank();

        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(vId));
    }

    /// @notice Verify that an arbitrary non-EP, non-self caller cannot call setRoot(Install[], bool, bytes)
    function check_SetRootPkgRejectsArbitraryCaller() external {
        address caller = address(uint160(uint256(keccak256("caller2"))));
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        MockValidator newValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        vm.startPrank(caller);
        try kernel.setRoot(pkgs, false, hex"") {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that setRoot(ValidationId) with an uninstalled validator reverts with InvalidVid
    function check_SetRootUninstalledValidatorReverts() external {
        MockValidator uninstalledValidator = new MockValidator();
        ValidationId vId = validatorToIdentifier(uninstalledValidator);

        vm.startPrank(address(ep));
        try kernel.setRoot(vId) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that setRoot with zero ValidationId (bytes21(0)) reverts on KernelUUPS
    function check_SetRootZeroVIdRevertsNoFallback() external {
        ValidationId zeroVId = ValidationId.wrap(bytes21(0));

        vm.startPrank(address(ep));
        try kernel.setRoot(zeroVId) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that setRoot with invalid validation type reverts with InvalidValidationType
    function check_SetRootInvalidValidationTypeReverts() external {
        // Construct a ValidationId with type byte 0x03 (invalid)
        bytes21 invalidVIdRaw = bytes21(uint168(0x030000000000000000000000000000000000000000));
        ValidationId invalidVId = ValidationId.wrap(invalidVIdRaw);

        vm.startPrank(address(ep));
        try kernel.setRoot(invalidVId) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that setRoot(Install[], bool, bytes) with empty packages reverts
    function check_SetRootPkgEmptyPackagesReverts() external {
        Install[] memory pkgs = new Install[](0);

        vm.startPrank(address(ep));
        try kernel.setRoot(pkgs, false, hex"") {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify that after setRoot, the root is updated correctly
    function check_SetRootUpdatesRoot() external {
        ValidationId oldRoot = kernel.root();
        ValidationId newRoot = validatorToIdentifier(secondValidator);

        assertTrue(ValidationId.unwrap(oldRoot) != ValidationId.unwrap(newRoot));

        vm.startPrank(address(ep));
        kernel.setRoot(newRoot);
        vm.stopPrank();

        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(newRoot));
    }
}
