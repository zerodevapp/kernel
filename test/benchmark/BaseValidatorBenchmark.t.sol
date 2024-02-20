// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";

import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {IKernel} from "src/interfaces/IKernel.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";
import {ValidationData} from "src/common/Types.sol";
import {Operation} from "src/common/Enums.sol";
import {ERC4337Utils} from "src/utils/ERC4337Utils.sol";

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";

import {MainnetMetering} from "gas-metering/MainnetMetering.sol";

import {JsonBenchmarkerTest} from "./JsonBenchmarker.sol";

using ERC4337Utils for IEntryPoint;
using ERC4337Utils for Kernel;

/// @dev Test contract used to perform benchmark of the differents validators
/// @author KONFeature
abstract contract BaseValidatorBenchmark is MainnetMetering, JsonBenchmarkerTest {
    // @dev The different 'master' wallets
    address private _factoryOwner;
    address private _fakeKernel;
    address payable private _userOpBeneficiary;

    /// @dev The kernel factory that will be used for the test
    KernelFactory private _factory;

    /// @dev The kernel account that will be used for the test
    Kernel private _kernel;
    address private _kernelImplementation;

    /// @dev The erc-4337 entrypoint that will be used for the test
    IEntryPoint internal _entryPoint;

    /// @dev The current validator we will benchmark
    IKernelValidator internal _validator;

    /// @dev dummy contract we will use to test user op
    DummyContract private _dummyContract;

    /// @dev Init the base stuff required to run the benchmark
    function _init() internal {
        // Prepare for gas mettering
        setUpMetering({verbose: false});

        // Init the json write
        _initJsonWriter();

        _dummyContract = new DummyContract();

        _factoryOwner = makeAddr("factoryOwner");
        _fakeKernel = makeAddr("fakeKernel");
        _userOpBeneficiary = payable(makeAddr("userOpBeneficiary"));

        // Init of the entry point
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        vm.label(ENTRYPOINT_0_6_ADDRESS, "EntryPoint");
        _entryPoint = IEntryPoint(payable(ENTRYPOINT_0_6_ADDRESS));

        // Deploy initial kernel implementation and factory
        _kernelImplementation = address(new Kernel(_entryPoint));
        vm.label(_kernelImplementation, "KernelImplementation");
        _factory = new KernelFactory(_factoryOwner, _entryPoint);

        // Allow the factory to create new kernel
        vm.prank(_factoryOwner);
        _factory.setImplementation(_kernelImplementation, true);
    }

    /// @dev Setup the test kernel account
    function _setupKernel() internal {
        // Deploy a kernel proxy account
        address deployedProxy = _factory.createAccount(_kernelImplementation, _getInitData(), 0);

        // Save this kernel in storage
        _kernel = Kernel(payable(deployedProxy));

        // Add him a few ether
        vm.deal(deployedProxy, 100 ether);
    }

    /// @dev Get the init data for the kernel
    function _getInitData() internal virtual returns (bytes memory) {
        bytes memory enableData = _getEnableData();
        return abi.encodeWithSelector(IKernel.initialize.selector, _validator, enableData);
    }

    /// @dev Get a signature with the sudo mode prefixed
    function _getSudoModeUserOpSignature(UserOperation memory userOpration) internal virtual returns (bytes memory) {
        bytes memory signature = _generateUserOpSignature(userOpration);
        return abi.encodePacked(bytes4(0x00000000), signature);
    }

    /// @dev Get the current output file name
    function _getOutputFileName() internal view virtual override returns (string memory) {
        return string.concat("mainnet_", _getValidatorName());
    }

    /* -------------------------------------------------------------------------- */
    /*                              Abstract methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the current validator anme (used for the json output)
    function _getValidatorName() internal view virtual returns (string memory);

    /// @dev The enabled data are used for mode 2, when the validator isn't enabled and should be enable before
    function _getEnableData() internal view virtual returns (bytes memory);

    /// @dev Fetch the data used to disable a kernel account
    function _getDisableData() internal view virtual returns (bytes memory);

    /// @dev Generate the signature for the given `_userOperation`
    function _generateUserOpSignature(UserOperation memory _userOperation) internal virtual returns (bytes memory);

    /// @dev Generate the signature for the given `_hash`
    function _generateHashSignature(bytes32 _hash) internal view virtual returns (bytes memory);

    /// @dev Generate the signature for the given `_hash`
    function _generateWrongHashSignature(bytes32 _hash) internal view virtual returns (bytes memory) {
        return _generateHashSignature(_hash | bytes32("0xdeadbeef"));
    }

    /* -------------------------------------------------------------------------- */
    /*                   Global methods (init, enable, disable)                   */
    /* -------------------------------------------------------------------------- */

    /// @dev Benchmark the enable of the given validator
    function test_fullDeployment() public manuallyMetered {
        // Don't save this in our gas measurement
        bytes memory initData = _getInitData();

        // Prepare the call to execute
        bytes memory call =
            abi.encodeWithSelector(KernelFactory.createAccount.selector, _kernelImplementation, initData, 0);

        // Perform the proxy deployment and init
        (uint256 gasConsumed,) = meterCall({
            from: address(0),
            to: address(_factory),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });
        _addToGlobal("fullDeployment", gasConsumed);
    }

    /// @dev Benchmark the enable of the given validator
    function test_enable() public manuallyMetered {
        // Don't save this in our gas measurement
        bytes memory enableData = _getEnableData();

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(IKernelValidator.enable.selector, enableData);

        // Perform the validator enable
        (uint256 gasConsumed,) = meterCall({
            from: address(_fakeKernel),
            to: address(_validator),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        _addToGlobal("enable", gasConsumed);
    }

    /// @dev Benchmark the disable of the given validator
    function test_disable() public manuallyMetered {
        // Don't save this in our gas measurement
        bytes memory disableData = _getDisableData();

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(IKernelValidator.disable.selector, disableData);

        // Perform the validator disable
        (uint256 gasConsumed,) = meterCall({
            from: address(_fakeKernel),
            to: address(_validator),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        _addToGlobal("disable", gasConsumed);
    }

    // TODO: Should we benchmark the different modes here?

    /* -------------------------------------------------------------------------- */
    /*                               User op methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Benchmark the user op validation process only
    function test_userOp_viaEntryPoint() public manuallyMetered {
        // Build a dummy user op
        (UserOperation memory userOperation,) = _getSignedDummyUserOp();

        // Build an array of user ops for the entry point
        UserOperation[] memory userOperations = new UserOperation[](1);
        userOperations[0] = userOperation;

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(IEntryPoint.handleOps.selector, userOperations, _userOpBeneficiary);

        // Perform the user op validation
        (uint256 gasConsumed,) = meterCall({
            from: address(0),
            to: address(_entryPoint),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        // Ensure it has done some dummy shit
        assertTrue(_dummyContract.hasDoneDummyShit(), "Should have done the dummy call");

        _addToUserOp("viaEntryPoint", gasConsumed);
    }

    /// @dev Benchmark the user op validation process only
    function test_userOp_viaKernel() public manuallyMetered {
        // Build a dummy user op
        (UserOperation memory userOperation, bytes32 userOperationHash) = _getSignedDummyUserOp();

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(Kernel.validateUserOp.selector, userOperation, userOperationHash, 0);

        // Perform the user op validation
        (uint256 gasConsumed,) = meterCall({
            from: address(_entryPoint),
            to: address(_kernel),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        // Ensure it hasn't done some dummy shit
        assertFalse(_dummyContract.hasDoneDummyShit(), "Shouldn't have executed the dummy call");

        _addToUserOp("validationViaKernel", gasConsumed);
    }

    /// @dev Benchmark the user op validation process only
    function test_userOp_viaValidator() public manuallyMetered {
        // Build a dummy user op
        (UserOperation memory userOperation, bytes32 userOperationHash) = _getSignedDummyUserOp();

        // Regen the signature, to have it not prefixed with the sude mode
        userOperation.signature = _generateUserOpSignature(userOperation);

        // Prepare the call to execute
        bytes memory call =
            abi.encodeWithSelector(IKernelValidator.validateUserOp.selector, userOperation, userOperationHash, 0);

        // Perform the user op validation
        (uint256 gasConsumed,) = meterCall({
            from: address(_entryPoint),
            to: address(_validator),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        // Ensure it hasn't done some dummy shit
        assertFalse(_dummyContract.hasDoneDummyShit(), "Shouldn't have executed the dummy call");

        _addToUserOp("validationViaValidator", gasConsumed);
    }

    /// @dev Get a dummy user op
    function _getDummyUserOp() private view returns (UserOperation memory) {
        bytes memory dummyCallData = abi.encodeWithSelector(DummyContract.doDummyShit.selector);
        bytes memory executeCallData =
            abi.encodeWithSelector(IKernel.execute.selector, address(_dummyContract), 0, dummyCallData, Operation.Call);
        return _entryPoint.fillUserOp(address(_kernel), executeCallData);
    }

    /// @dev Get a dummy user op
    function _getSignedDummyUserOp() private returns (UserOperation memory userOperation, bytes32 userOperationHash) {
        userOperation = _getDummyUserOp();
        userOperation.signature = _getSudoModeUserOpSignature(userOperation);

        // Get the hash of the user operation
        userOperationHash = _entryPoint.getUserOpHash(userOperation);
    }

    /* -------------------------------------------------------------------------- */
    /*                               User op methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Benchmark on a direct signature validation on the validator level
    function test_signature_viaValidator() public manuallyMetered {
        bytes32 _hash = keccak256("0xacab");
        bytes memory signature = _generateHashSignature(_hash);

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(IKernelValidator.validateSignature.selector, _hash, signature);

        // Perform the validator signature check directly
        (uint256 gasConsumed,) = meterCall({
            from: address(_kernel),
            to: address(_validator),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        _addToSignature("viaValidator", gasConsumed);
    }

    /// @dev Benchmark on a direct signature validation on the kernel level
    function test_signature_viaKernel() public manuallyMetered {
        bytes32 _hash = keccak256("0xacab");
        // Get a few data for the domain separator
        bytes32 domainSeparator = _kernel.getDomainSeparator();
        // Should create a digest of the hash
        bytes32 _digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, _hash));
        bytes memory signature = _generateHashSignature(_digest);

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(Kernel.isValidSignature.selector, _hash, signature);

        // Perform the validator signature check directly
        (uint256 gasConsumed,) = meterCall({
            from: address(0),
            to: address(_kernel),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });
        _addToSignature("viaKernel", gasConsumed);
    }

    /// @dev Benchmark on a direct signature validation on the validator level
    function test_signature_ko_viaValidator() public manuallyMetered {
        bytes32 _hash = keccak256("0xacab");
        bytes memory signature = _generateWrongHashSignature(_hash);

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(IKernelValidator.validateSignature.selector, _hash, signature);

        // Perform the validator signature check directly
        (uint256 gasConsumed,) = meterCall({
            from: address(_kernel),
            to: address(_validator),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        _addToSignature("ko_viaValidator", gasConsumed);
    }

    /// @dev Benchmark on a direct signature validation on the kernel level
    function test_signature_ko_viaKernel() public manuallyMetered {
        bytes32 _hash = keccak256("0xacab");
        // Get a few data for the domain separator
        bytes32 domainSeparator = _kernel.getDomainSeparator();
        // Should create a digest of the hash
        bytes32 _digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, _hash));
        bytes memory signature = _generateWrongHashSignature(_digest);

        // Prepare the call to execute
        bytes memory call = abi.encodeWithSelector(Kernel.isValidSignature.selector, _hash, signature);

        // Perform the validator signature check directly
        (uint256 gasConsumed,) = meterCall({
            from: address(0),
            to: address(_kernel),
            callData: call,
            value: 0,
            transaction: true,
            expectRevert: false
        });
        _addToSignature("ko_viaKernel", gasConsumed);
    }

    /* -------------------------------------------------------------------------- */
    /*                               Utility methods                              */
    /* -------------------------------------------------------------------------- */

    function _addToGlobal(string memory _testCase, uint256 _gasUsed) private {
        _addResult("global", _testCase, _gasUsed);
    }

    function _addToUserOp(string memory _testCase, uint256 _gasUsed) private {
        _addResult("userOp", _testCase, _gasUsed);
    }

    function _addToSignature(string memory _testCase, uint256 _gasUsed) private {
        _addResult("signature", _testCase, _gasUsed);
    }
}

/// @dev Dummy contract used to test the validator
contract DummyContract {
    bool private _hasDoneDummyShit = false;

    function doDummyShit() public {
        bytes32 randomHash = keccak256("0xdeadbeef");
        bytes memory randomData = abi.encodePacked(randomHash);
        randomHash = keccak256(randomData);

        _hasDoneDummyShit = true;
    }

    function hasDoneDummyShit() public view returns (bool) {
        return _hasDoneDummyShit;
    }
}
