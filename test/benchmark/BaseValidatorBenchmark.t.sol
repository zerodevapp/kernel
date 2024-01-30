// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";

import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {CREATOR_0_6_BYTECODE, CREATOR_0_6_ADDRESS} from "I4337/artifacts/EntryPoint_0_6.sol";

/// @dev Test contract used to perform benchmark of the differents validators
/// @author KONFeature
abstract contract BaseValidatorBenchmark is Test {
    // @dev The different 'master' wallets
    address private _factoryOwner;
    address private _fakeKernel;

    /// @dev The kernel factory that will be used for the test
    KernelFactory private _factory;

    /// @dev The kernel account that will be used for the test
    Kernel private _kernel;
    address private _kernelImplementation;

    /// @dev The erc-4337 entrypoint that will be used for the test
    IEntryPoint private _entryPoint;

    /// @dev The current validator we will benchmark
    IKernelValidator internal _validator;

    /// @dev The JSON output of the benchmark
    string private _jsonOutput = "global json";
    string private _currentJson;

    // Global benchmark config
    bool private _isWriteEnabled;

    /// @dev Init the base stuff required to run the benchmark
    function _init() internal {
        _isWriteEnabled = vm.envOr("WRITE_BENCHMARK_RESULT", false);

        (_factoryOwner,) = makeAddrAndKey("factoryOwner");
        (_fakeKernel,) = makeAddrAndKey("fakeKernel");

        // Init of the entry point
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        _entryPoint = IEntryPoint(payable(ENTRYPOINT_0_6_ADDRESS));

        // Deploy initial kernel implementation and factory
        _kernelImplementation = address(new Kernel(_entryPoint));
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

    /* -------------------------------------------------------------------------- */
    /*                              Abstract methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the current validator anme (used for the json output)
    function _getValidatorName() internal view virtual returns (string memory);

    /// @dev The enabled data are used for mode 2, when the validator isn't enabled and should be enable before
    function _getEnableData() internal view virtual returns (bytes memory);

    /// @dev Fetch the data used to disable a kernel account
    function _getDisableData() internal view virtual returns (bytes memory);

    /// @dev Get the initialisation data for the current validator
    function _getInitData() internal view virtual returns (bytes memory);

    /// @dev Generate the signature for the given `_userOperation`
    function _generateUserOpSignature(UserOperation memory _userOperation)
        internal
        view
        virtual
        returns (bytes memory);

    /// @dev Generate the signature for the given `_hash`
    function _generateHashSignature(bytes32 _hash) internal view virtual returns (bytes memory);

    /* -------------------------------------------------------------------------- */
    /*                              Run the banchmark                             */
    /* -------------------------------------------------------------------------- */

    /// @dev Run the whole benchmark
    function test_benchmark() public {
        string memory validatorName = _getValidatorName();
        console.log("=====================================");
        console.log("Benchmarking: %s", validatorName);
        console.log("=====================================");

        // Run the global methods
        console.log("Global:");
        _currentJson = "global";
        _benchmark_fullDeployment();
        _benchmark_enable();
        _benchmark_disable();
        _addToGlobalJson("global");

        // Run the user op related tests
        console.log("User op:");
        // TODO
        _addToGlobalJson("userOp");

        // Run the signature related test
        console.log("Signature:");
        // TODO
        _addToGlobalJson("signature");

        // Write the json output
        if(_isWriteEnabled) {
            string memory fileName = string.concat("./benchmarks/validator/", validatorName, ".json");
            vm.writeJson(_jsonOutput, fileName);
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                   Global methods (init, enable, disable)                   */
    /* -------------------------------------------------------------------------- */

    /// @dev Benchmark the enable of the given validator
    function _benchmark_fullDeployment() private {
        // Don't save this in our gas measurement
        bytes memory initData = _getInitData();

        // Perform the proxy deployment and init
        uint256 gasConsumed = gasleft();
        _factory.createAccount(_kernelImplementation, initData, 0);
        gasConsumed = gasConsumed - gasleft();
        _addToGlobal("fullDeployment", gasConsumed);
    }

    /// @dev Benchmark the enable of the given validator
    function _benchmark_enable() private {
        // Don't save this in our gas measurement
        bytes memory enableData = _getEnableData();

        // Perform the validator enable
        uint256 gasConsumed = gasleft();
        vm.prank(_fakeKernel);
        _validator.enable(enableData);
        gasConsumed = gasConsumed - gasleft();
        _addToGlobal("enable", gasConsumed);
    }

    /// @dev Benchmark the disable of the given validator
    function _benchmark_disable() private {
        // Don't save this in our gas measurement
        bytes memory disableData = _getDisableData();

        // Perform the validator disable
        uint256 gasConsumed = gasleft();
        vm.prank(_fakeKernel);
        _validator.disable(disableData);
        gasConsumed = gasConsumed - gasleft();
        _addToGlobal("disable", gasConsumed);
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

    /// @dev Add benchmark result to the json and log it
    function _addResult(string memory _key, string memory _testCase, uint256 _gasUsed) private {
        // Log the output
        console.log("- case: %s", _testCase);
        console.log("    gas : ", _gasUsed);

        // Add it to the json
        if (_isWriteEnabled) {
            _currentJson = vm.serializeUint(_key, _testCase, _gasUsed);
        }
    }

    /// @dev Add the current json to the output one
    function _addToGlobalJson(string memory _globalTest) private {
        // Add the current json to the global one
        if (_isWriteEnabled) {
            _jsonOutput = vm.serializeString("final", _globalTest, _currentJson);
        }
        // Reset the current json
        _currentJson = "";
    }
}
