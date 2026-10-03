// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {PermissionId} from "src/types/Types.sol";
import {InvalidNonce, InstallSignatureVerificationFailed} from "src/types/Error.sol";
import {KernelHelper} from "../KernelHelper.sol";

abstract contract Kernel_installModuleWithSignature is BTTModifiers {
    // State variables for installModuleWithSignature branch tracking
    bool internal _replayable;
    bool internal _signatureValid;
    bool internal _nonceValid;

    modifier whenReplayableIsFalse() {
        _replayable = false;
        _;
    }

    modifier givenTheSignatureIsValidForThisChain() {
        _signatureValid = true;
        _;
    }

    modifier givenTheNonceIsValid() {
        _nonceValid = true;
        _;
    }

    function test_GivenTheNonceIsValid()
        external
        whenReplayableIsFalse
        givenTheSignatureIsValidForThisChain
        givenTheNonceIsValid
    {
        // it should verify the root validator signature
        // it should increment the nonce
        // it should install all packages
        // it should emit ModuleInstalled events for each package
        MockValidator testValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        // Create valid signature for nonce 0
        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);

        kernel.installModule(false, 0, packages, signature);

        // Verify the validator was installed
        assertTrue(kernel.isModuleInstalled(1, address(testValidator), ""), "Validator should be installed");

        // Verify nonce was incremented by trying to use same nonce again - should fail
        MockValidator testValidator2 = new MockValidator();
        Install[] memory packages2 = new Install[](1);
        packages2[0] = Install({moduleType: 1, module: address(testValidator2), moduleData: hex"", internalData: hex""});

        bytes32 digest2 = KernelHelper.installDigest(address(kernel), false, 0, packages2);
        bytes memory signature2 = _rootSignHash(digest2, true);

        vm.expectRevert(InvalidNonce.selector);
        kernel.installModule(false, 0, packages2, signature2);
    }

    function test_GivenTheNonceIsInvalid() external whenReplayableIsFalse givenTheSignatureIsValidForThisChain {
        // it should revert with InvalidNonce error
        MockValidator testValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        // First use nonce 0 to consume it
        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);
        kernel.installModule(false, 0, packages, signature);

        // Try to use nonce 0 again - should fail
        MockValidator testValidator2 = new MockValidator();
        Install[] memory packages2 = new Install[](1);
        packages2[0] = Install({moduleType: 1, module: address(testValidator2), moduleData: hex"", internalData: hex""});

        bytes32 digest2 = KernelHelper.installDigest(address(kernel), false, 0, packages2);
        bytes memory signature2 = _rootSignHash(digest2, true);

        vm.expectRevert(InvalidNonce.selector);
        kernel.installModule(false, 0, packages2, signature2);
    }

    function test_GivenTheSignatureIsInvalid() external whenReplayableIsFalse {
        // it should revert with InstallSignatureVerificationFailed error
        MockValidator testValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        // Create invalid signature
        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, false); // false = invalid

        vm.expectRevert(InstallSignatureVerificationFailed.selector);
        kernel.installModule(false, 0, packages, signature);
    }

    modifier whenReplayableIsTrue() {
        _replayable = true;
        _;
    }

    modifier givenTheSignatureIsValid() {
        _signatureValid = true;
        _;
    }

    modifier givenTheNonceIsValidOnThisChain() {
        _nonceValid = true;
        _;
    }

    function test_GivenTheNonceIsValidOnThisChain()
        external
        whenReplayableIsTrue
        givenTheSignatureIsValid
        givenTheNonceIsValidOnThisChain
    {
        // it should verify the root validator signature
        // it should increment the nonce on this chain
        // it should install all packages
        // it should allow the same signature on different chains
        MockValidator testValidator = new MockValidator();
        testValidator.sudoSetSuccess(true);

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        // Create replayable signature (without chainId)
        bytes32 digest = KernelHelper.installDigest(address(kernel), true, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);

        kernel.installModule(true, 0, packages, signature);

        // Verify the validator was installed
        assertTrue(kernel.isModuleInstalled(1, address(testValidator), ""), "Validator should be installed");
    }

    function test_GivenTheNonceIsInvalidOnThisChain() external whenReplayableIsTrue givenTheSignatureIsValid {
        // it should revert with InvalidNonce error
        MockValidator testValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        // First use nonce 0
        bytes32 digest = KernelHelper.installDigest(address(kernel), true, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);
        kernel.installModule(true, 0, packages, signature);

        // Try to use nonce 0 again with replayable = true
        MockValidator testValidator2 = new MockValidator();
        Install[] memory packages2 = new Install[](1);
        packages2[0] = Install({moduleType: 1, module: address(testValidator2), moduleData: hex"", internalData: hex""});

        bytes32 digest2 = KernelHelper.installDigest(address(kernel), true, 0, packages2);
        bytes memory signature2 = _rootSignHash(digest2, true);

        vm.expectRevert(InvalidNonce.selector);
        kernel.installModule(true, 0, packages2, signature2);
    }

    function test_GivenTheSignatureIsInvalid_WhenReplayableIsTrue() external whenReplayableIsTrue {
        // it should revert with InstallSignatureVerificationFailed error
        MockValidator testValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        // Create invalid signature (replayable)
        bytes32 digest = KernelHelper.installDigest(address(kernel), true, 0, packages);
        bytes memory signature = _rootSignHash(digest, false); // false = invalid

        vm.expectRevert(InstallSignatureVerificationFailed.selector);
        kernel.installModule(true, 0, packages, signature);
    }

    function test_GivenPackagesContainAValidator() external {
        // it should install the validator with allowed selectors without changing root
        MockValidator testValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(testValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(bytes4(keccak256("execute(bytes32,bytes)")))
        });

        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);

        kernel.installModule(false, 0, packages, signature);

        // Validator should be installed
        assertTrue(kernel.isModuleInstalled(1, address(testValidator), ""), "Validator should be installed");

        assertTrue(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(testValidator)))).installed,
            "Validator should be marked installed"
        );
    }

    function test_GivenPackagesContainAnExecutor() external {
        // it should install the executor with its hook
        MockExecutor testExecutor = new MockExecutor();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 2, module: address(testExecutor), moduleData: hex"", internalData: hex""});

        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);

        kernel.installModule(false, 0, packages, signature);

        assertTrue(kernel.isModuleInstalled(2, address(testExecutor), ""), "Executor should be installed");
    }

    function test_GivenPackagesContainAFallbackHandler() external {
        // it should register the selector to the fallback
        MockFallback testFallback = new MockFallback();
        bytes4 selector = bytes4(keccak256("testFallbackFunction()"));

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 3,
            module: address(testFallback),
            moduleData: hex"",
            internalData: abi.encodePacked(selector, bytes1(0x00))
        });

        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);

        kernel.installModule(false, 0, packages, signature);

        assertTrue(
            kernel.isModuleInstalled(3, address(testFallback), abi.encodePacked(selector)),
            "Fallback should be registered for selector"
        );
    }

    function test_GivenPackagesContainPoliciesAndSignerForAPermission() external {
        // it should install all policies for the permissionId
        // it should install the signer for the permissionId
        MockPolicy testPolicy = new MockPolicy();
        MockSigner testSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("sigInstallPermission")));

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5, module: address(testPolicy), moduleData: hex"", internalData: abi.encodePacked(testPermId)
        });
        packages[1] = Install({
            moduleType: 6, module: address(testSigner), moduleData: hex"", internalData: abi.encodePacked(testPermId)
        });

        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        bytes memory signature = _rootSignHash(digest, true);

        kernel.installModule(false, 0, packages, signature);

        assertTrue(
            kernel.isModuleInstalled(5, address(testPolicy), abi.encodePacked(testPermId)),
            "Policy should be installed for permissionId"
        );
        assertTrue(
            kernel.isModuleInstalled(6, address(testSigner), abi.encodePacked(testPermId)),
            "Signer should be installed for permissionId"
        );
    }
}
