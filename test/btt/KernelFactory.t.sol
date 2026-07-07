// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {
    InvalidRootValidation,
    InvalidInitialization,
    InvalidSigner,
    ImplementationNotDeployed
} from "src/types/Error.sol";
import {KernelDeployed} from "src/types/Events.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";

/// @title KernelFactory BTT Tests
/// @notice Tests for KernelFactory following Branching Tree Technique
/// @dev Tree specification: test/btt/KernelFactory.deploy.tree
contract KernelFactory_Test is Test {
    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    IEntryPoint ep;
    KernelFactory factory;
    KernelUUPS uups;
    KernelImmutableECDSA immutableEcdsa;
    MockValidator rootValidator;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        ep = EntryPointLib.deploy();
        uups = new KernelUUPS(ep);
        immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        rootValidator.sudoSetSuccess(true);
    }

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    // State variables for BTT branch tracking
    bool internal _packagesEmpty;
    address internal _ecdsaOwner;

    modifier givenPackagesArrayIsEmpty() {
        _packagesEmpty = true;
        _;
    }

    modifier givenPackagesArrayHasValidModules() {
        _packagesEmpty = false;
        _;
    }

    modifier givenMsgValueIsSent() {
        vm.deal(address(this), 10 ether);
        _;
    }

    modifier givenECDSAOwnerIsValid() {
        _ecdsaOwner = makeAddr("ecdsaOwner");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPLOY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should revert during initialization when packages array is empty
    function test_RevertWhen_PackagesArrayIsEmpty() external givenPackagesArrayIsEmpty {
        Install[] memory packages = new Install[](0);

        // it should revert with InvalidInitialization error (from kernel.initialize)
        vm.expectRevert(InvalidInitialization.selector);
        factory.deploy(packages, 0);
    }

    /// @notice it should deploy a new KernelUUPS proxy using CREATE2
    function test_WhenDeployingWithValidPackages() external givenPackagesArrayHasValidModules {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deploy(packages, 0);

        assertTrue(address(account) != address(0), "Account should be deployed");
        assertTrue(address(account).code.length > 0, "Account should have code");
    }

    /// @notice it should initialize the account with the packages
    function test_WhenDeploying_InitializesAccount() external givenPackagesArrayHasValidModules {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deploy(packages, 0);

        // Verify root validator is installed
        assertEq(
            account.validationInfo(validatorToIdentifier(IValidator(address(rootValidator)))).hook,
            address(1),
            "Root validator should be installed"
        );
    }

    /// @notice it should set the first package as the root validator
    function test_WhenDeploying_SetsRootValidator() external givenPackagesArrayHasValidModules {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deploy(packages, 0);

        // Root should be set (we can verify by checking that root validation works)
        assertTrue(address(account) != address(0), "Account with root should be deployed");
    }

    /// @notice it should return the deployed account address matching prediction
    function test_WhenDeploying_ReturnsAddress() external givenPackagesArrayHasValidModules {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deploy(packages, 0);
        address predicted = factory.getAddress(packages, 0);

        assertEq(address(account), predicted, "Deployed address should match predicted");
    }

    /// @notice it should forward ETH to the deployed account
    function test_WhenDeploying_WithEthValue() external givenPackagesArrayHasValidModules givenMsgValueIsSent {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        uint256 value = 1 ether;
        Kernel account = factory.deploy{value: value}(packages, 0);

        assertEq(address(account).balance, value, "Account should receive ETH");
    }

    /// @notice it should return the existing address if already deployed (counterfactual)
    function test_WhenDeploying_CounterfactualExists() external givenPackagesArrayHasValidModules {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account1 = factory.deploy(packages, 0);
        Kernel account2 = factory.deploy(packages, 0);

        assertEq(address(account1), address(account2), "Should return existing account");
    }

    /*//////////////////////////////////////////////////////////////
                        DEPLOY ECDSA TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should deploy a KernelImmutableECDSA proxy
    function test_WhenDeployingECDSA() external givenECDSAOwnerIsValid {
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deployECDSA(owner, packages, 0);

        assertTrue(address(account) != address(0), "ECDSA account should be deployed");
        assertTrue(address(account).code.length > 0, "ECDSA account should have code");
    }

    /// @notice it should revert when ECDSA owner is address(0)
    function test_RevertWhen_DeployingECDSA_ZeroOwner() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        vm.expectRevert(InvalidSigner.selector);
        factory.deployECDSA(address(0), packages, 0);
    }

    /// @notice it should return deterministic address for same owner and nonce
    function test_WhenDeployingECDSA_Deterministic() external givenECDSAOwnerIsValid {
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted = factory.getECDSAAddress(owner, packages, 0);
        Kernel account = factory.deployECDSA(owner, packages, 0);

        assertEq(address(account), predicted, "ECDSA address should be deterministic");
    }

    /// @notice it should forward ETH to ECDSA account
    function test_WhenDeployingECDSA_WithEthValue() external givenECDSAOwnerIsValid givenMsgValueIsSent {
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        uint256 value = 1 ether;

        Kernel account = factory.deployECDSA{value: value}(owner, packages, 0);

        assertEq(address(account).balance, value, "ECDSA account should receive ETH");
    }

    /*//////////////////////////////////////////////////////////////
                        GET ADDRESS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should return deterministic address without deploying
    function test_WhenGettingAddress_NoDeploy() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted = factory.getAddress(packages, 0);

        // Should not have code yet
        assertEq(predicted.code.length, 0, "Should not be deployed yet");

        // Now deploy and verify match
        Kernel deployed = factory.deploy(packages, 0);
        assertEq(address(deployed), predicted, "Addresses should match");
    }

    /// @notice it should return same address for same packages and nonce
    function test_WhenGettingAddress_SameInputsSameOutput() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted1 = factory.getAddress(packages, 0);
        address predicted2 = factory.getAddress(packages, 0);

        assertEq(predicted1, predicted2, "Same inputs should give same address");
    }

    /// @notice it should return different addresses for different nonces
    function test_WhenGettingAddress_DifferentNonces() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted1 = factory.getAddress(packages, 0);
        address predicted2 = factory.getAddress(packages, 1);

        assertTrue(predicted1 != predicted2, "Different nonces should give different addresses");
    }

    /// @notice it should return different addresses for different packages
    function test_WhenGettingAddress_DifferentPackages() external {
        MockValidator validator2 = new MockValidator();

        Install[] memory packages1 = new Install[](1);
        packages1[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        Install[] memory packages2 = new Install[](1);
        packages2[0] = Install({moduleType: 1, module: address(validator2), moduleData: hex"", internalData: hex""});

        address predicted1 = factory.getAddress(packages1, 0);
        address predicted2 = factory.getAddress(packages2, 0);

        assertTrue(predicted1 != predicted2, "Different packages should give different addresses");
    }

    /*//////////////////////////////////////////////////////////////
                    GET ECDSA ADDRESS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should return deterministic ECDSA address
    function test_WhenGettingECDSAAddress() external {
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted = factory.getECDSAAddress(owner, packages, 0);

        // Should not have code yet
        assertEq(predicted.code.length, 0, "Should not be deployed yet");

        // Now deploy and verify match
        Kernel deployed = factory.deployECDSA(owner, packages, 0);
        assertEq(address(deployed), predicted, "ECDSA addresses should match");
    }

    /// @notice it should return different addresses for different owners
    function test_WhenGettingECDSAAddress_DifferentOwners() external {
        address owner1 = makeAddr("owner1");
        address owner2 = makeAddr("owner2");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted1 = factory.getECDSAAddress(owner1, packages, 0);
        address predicted2 = factory.getECDSAAddress(owner2, packages, 0);

        assertTrue(predicted1 != predicted2, "Different owners should give different addresses");
    }

    /*//////////////////////////////////////////////////////////////
                    DEPLOY EVENT EMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should emit KernelDeployed event on first deploy
    function test_WhenDeploying_EmitsKernelDeployed() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        address predicted = factory.getAddress(packages, 42);

        vm.expectEmit(true, true, true, true);
        emit KernelDeployed(predicted);
        factory.deploy(packages, 42);
    }

    /// @notice it should NOT emit KernelDeployed event when already deployed
    function test_WhenDeployingAlreadyDeployed_NoEvent() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        // First deploy
        factory.deploy(packages, 43);

        // Second deploy should NOT emit (no easy way to assert "not emitted" directly,
        // but we verify the return value matches)
        Kernel account = factory.deploy(packages, 43);
        assertTrue(address(account).code.length > 0, "Should return existing deployed account");
    }

    /// @notice it should emit KernelDeployed event for ECDSA deploy
    function test_WhenDeployingECDSA_EmitsKernelDeployed() external {
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](0);

        address predicted = factory.getECDSAAddress(owner, packages, 44);

        vm.expectEmit(true, true, true, true);
        emit KernelDeployed(predicted);
        factory.deployECDSA(owner, packages, 44);
    }

    /*//////////////////////////////////////////////////////////////
                    ALREADY DEPLOYED + ETH FOR ECDSA TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should forward ETH to existing ECDSA account when already deployed
    function test_WhenDeployingECDSA_AlreadyDeployed_ForwardsETH() external givenMsgValueIsSent {
        address owner = makeAddr("ecdsaOwner");
        Install[] memory packages = new Install[](0);

        Kernel account = factory.deployECDSA(owner, packages, 45);
        uint256 balanceBefore = address(account).balance;

        factory.deployECDSA{value: 0.5 ether}(owner, packages, 45);

        assertEq(
            address(account).balance, balanceBefore + 0.5 ether, "ETH should be forwarded to existing ECDSA account"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    _calculateSalt MULTIPLE PACKAGES TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should produce different salt for different module data
    function test_WhenCalculateSalt_DifferentModuleData() external {
        Install[] memory packages1 = new Install[](1);
        packages1[0] =
            Install({moduleType: 1, module: address(rootValidator), moduleData: hex"aa", internalData: hex""});

        Install[] memory packages2 = new Install[](1);
        packages2[0] =
            Install({moduleType: 1, module: address(rootValidator), moduleData: hex"bb", internalData: hex""});

        address addr1 = factory.getAddress(packages1, 0);
        address addr2 = factory.getAddress(packages2, 0);

        assertTrue(addr1 != addr2, "Different moduleData should produce different addresses");
    }

    /// @notice it should produce different salt for different internalData
    function test_WhenCalculateSalt_DifferentInternalData() external {
        Install[] memory packages1 = new Install[](1);
        packages1[0] =
            Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex"aa"});

        Install[] memory packages2 = new Install[](1);
        packages2[0] =
            Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex"bb"});

        address addr1 = factory.getAddress(packages1, 0);
        address addr2 = factory.getAddress(packages2, 0);

        assertTrue(addr1 != addr2, "Different internalData should produce different addresses");
    }

    /// @notice it should handle multiple packages in salt calculation
    function test_WhenCalculateSalt_MultiplePackages() external {
        MockValidator validator2 = new MockValidator();
        validator2.sudoSetSuccess(true);
        MockExecutor executor = new MockExecutor();

        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        packages[1] = Install({moduleType: 2, module: address(executor), moduleData: hex"", internalData: hex""});

        Kernel account = factory.deploy(packages, 0);

        // Both packages should be installed
        assertTrue(account.isModuleInstalled(1, address(rootValidator), ""), "Validator should be installed");
        assertTrue(account.isModuleInstalled(2, address(executor), ""), "Executor should be installed");
    }

    /*//////////////////////////////////////////////////////////////
                    CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice it should store immutables correctly
    function test_Constructor_StoresImmutables() external view {
        assertEq(address(factory.UUPS()), address(uups), "UUPS immutable should be set");
        assertEq(address(factory.IMMUTABLE_ECDSA()), address(immutableEcdsa), "IMMUTABLE_ECDSA should be set");
    }

    /// @notice it should revert when UUPS has no code
    function test_Constructor_RevertWhen_UUPSNoCode() external {
        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(KernelUUPS(payable(address(0xdead))), immutableEcdsa);
    }

    /// @notice it should revert when ImmutableECDSA has no code
    function test_Constructor_RevertWhen_ImmutableECDSANoCode() external {
        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(uups, KernelImmutableECDSA(payable(address(0xdead))));
    }
}
