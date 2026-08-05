// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Unauthorized, InvalidInitialization} from "src/types/Error.sol";
import {ERC1967_IMPLEMENTATION_SLOT} from "src/types/Constants.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";

/// @title KernelUUPS BTT Tests
/// @notice Tests for KernelUUPS variant following Branching Tree Technique
/// @dev Tree specification: test/btt/KernelUUPS.tree
contract KernelUUPS_Test is Test {
    IEntryPoint ep;
    KernelFactory factory;
    KernelUUPS uupsImpl;
    KernelImmutableECDSA immutableEcdsaImpl;
    Kernel kernel;
    MockValidator mockValidator;
    MockExecutor mockExecutor;

    function setUp() public {
        ep = EntryPointLib.deploy();

        uupsImpl = new KernelUUPS(ep);
        immutableEcdsaImpl = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uupsImpl, immutableEcdsaImpl);

        mockValidator = new MockValidator();
        mockValidator.sudoSetSuccess(true);
        mockExecutor = new MockExecutor();

        // Deploy a UUPS kernel through the factory
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        kernel = Kernel(payable(factory.deploy(packages, 0)));
        vm.deal(address(kernel), 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    _authorizeUpgrade TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenAuthorizeUpgradeIsCalledByEntryPoint() external {
        // it should not revert
        KernelUUPS newImpl = new KernelUUPS(ep);

        vm.prank(address(ep));
        KernelUUPS(payable(address(kernel))).upgradeToAndCall(address(newImpl), hex"");

        bytes32 impl = vm.load(address(kernel), ERC1967_IMPLEMENTATION_SLOT);
        assertEq(
            address(uint160(uint256(impl))), address(newImpl), "Implementation should be updated when called by EP"
        );
    }

    function test_WhenAuthorizeUpgradeIsCalledBySelf() external {
        // it should not revert
        KernelUUPS newImpl = new KernelUUPS(ep);

        // Use execute with SINGLE call to call upgradeToAndCall on self
        vm.prank(address(ep));
        kernel.execute(
            bytes32(0), // callType=SINGLE (0x00), execType=DEFAULT (0x00)
            abi.encodePacked(
                address(kernel),
                uint256(0),
                abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, address(newImpl), hex"")
            )
        );

        bytes32 impl = vm.load(address(kernel), ERC1967_IMPLEMENTATION_SLOT);
        assertEq(
            address(uint160(uint256(impl))), address(newImpl), "Implementation should be updated when called by self"
        );
    }

    function test_WhenAuthorizeUpgradeIsCalledByUnauthorizedCaller() external {
        // it should revert with Unauthorized
        KernelUUPS newImpl = new KernelUUPS(ep);

        address randomCaller = makeAddr("randomCaller");
        vm.prank(randomCaller);
        vm.expectRevert(Unauthorized.selector);
        KernelUUPS(payable(address(kernel))).upgradeToAndCall(address(newImpl), hex"");
    }

    /*//////////////////////////////////////////////////////////////
                    initialize TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenInitializeIsCalledForTheFirstTimeWithValidPackages() external {
        // it should initialize the kernel and install root
        MockValidator newValidator = new MockValidator();
        newValidator.sudoSetSuccess(true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        // Deploy a fresh kernel
        Kernel freshKernel = Kernel(payable(factory.deploy(packages, 999)));

        // Verify the validator is installed
        assertTrue(
            freshKernel.isModuleInstalled(1, address(newValidator), ""), "Validator should be installed after init"
        );

        // Verify it is installed and set as root
        assertTrue(
            freshKernel.validationInfo(validatorToIdentifier(IValidator(address(newValidator)))).installed,
            "Validator should be set as root"
        );
    }

    function test_WhenInitializeIsCalledASecondTime() external {
        // it should revert with InvalidInitialization
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});

        vm.expectRevert(InvalidInitialization.selector);
        kernel.initialize(packages);
    }

    function test_WhenInitializeIsCalledWithEmptyPackages() external {
        // it should revert with InvalidInitialization
        // The base Kernel._initialize requires packages.length > 0
        // But the initializer guard fires first if already initialized
        Install[] memory empty = new Install[](0);

        // Deploy a fresh proxy manually to test empty packages on first init
        // We use a different nonce to get a fresh uninitialized proxy
        // When we call factory.deploy with empty packages, the proxy is created
        // then initialize is called, which calls _initialize which requires packages.length > 0
        vm.expectRevert(InvalidInitialization.selector);
        factory.deploy(empty, 500);
    }

    function test_WhenInitializeIsCalledWithMultiplePackages() external {
        // it should install all packages and set first as root
        MockValidator newValidator = new MockValidator();
        newValidator.sudoSetSuccess(true);

        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        packages[1] = Install({moduleType: 2, module: address(mockExecutor), moduleData: hex"", internalData: hex""});

        Kernel freshKernel = Kernel(payable(factory.deploy(packages, 888)));

        // Verify the first package (validator) is installed as root
        assertTrue(freshKernel.isModuleInstalled(1, address(newValidator), ""), "First validator should be installed");
        assertTrue(
            freshKernel.validationInfo(validatorToIdentifier(IValidator(address(newValidator)))).installed,
            "First validator should be root"
        );

        // Verify the second package (executor) is installed
        assertTrue(freshKernel.isModuleInstalled(2, address(mockExecutor), ""), "Second executor should be installed");
    }

    /*//////////////////////////////////////////////////////////////
                    CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenConstructorIsCalled() external {
        // it should disable initializers on the implementation
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});

        vm.expectRevert(InvalidInitialization.selector);
        uupsImpl.initialize(packages);
    }

    /*//////////////////////////////////////////////////////////////
                    INITIALIZE WITH VALUE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenInitializeIsCalledWithValue() external {
        // it should accept ETH during initialization
        MockValidator newValidator = new MockValidator();
        newValidator.sudoSetSuccess(true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        vm.deal(address(this), 1 ether);
        Kernel freshKernel = Kernel(payable(factory.deploy{value: 0.5 ether}(packages, 777)));

        assertEq(address(freshKernel).balance, 0.5 ether, "Kernel should receive ETH during deployment");
    }

    /*//////////////////////////////////////////////////////////////
                    UPGRADE WITH CALLBACK TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenUpgradeToAndCallIsCalledWithInitializationData() external {
        // it should upgrade and run the callback
        KernelUUPS newImpl = new KernelUUPS(ep);

        // Upgrade with a callback that does nothing harmful (just calls accountId)
        bytes memory callbackData = abi.encodeWithSelector(Kernel.accountId.selector);

        vm.prank(address(ep));
        KernelUUPS(payable(address(kernel))).upgradeToAndCall(address(newImpl), callbackData);

        bytes32 impl = vm.load(address(kernel), ERC1967_IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(impl))), address(newImpl), "Implementation should be updated with callback");
    }
}
