// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

import {LibString} from "solady/utils/LibString.sol";
import {ERC4337Utils} from "src/utils/ERC4337Utils.sol";
import {MainnetMetering} from "gas-metering/MainnetMetering.sol";

/// @dev Global test contract that will output benchmark result inside a json file
/// @notice Build to output a json like that: {"network": {"testCase": "gasUsed"}}
/// @author KONFeature
abstract contract JsonBenchmarkerTest is Test {

    /// @dev File path for the base json file (that will be copy pasted for new tests)
    string private constant _baseJsonFilePath = "./gas/validator/base.json";

    /// @dev Check if the json writer is enabled or not
    bool private _isWriteEnabled;

    /// @dev The key we will use to write stuff in our json, to parallelise a few things
    string private _writerKey;

    /// @dev The JSON output of the benchmark
    string private _outputFilePath;

    /// @dev Init the base stuff required to run the benchmark
    function _initJsonWriter() internal {
        _isWriteEnabled = vm.envOr("WRITE_BENCHMARK_RESULT", false);

        // Early exit if write not enable
        if (!_isWriteEnabled) {
            return;
        }

        // Check if the file exist
        _outputFilePath = string.concat("./gas/validator/", _getOutputFileName(), ".json");
        if (!vm.exists(_outputFilePath)) {
            // If not, create the initial version of it
            vm.copyFile(_baseJsonFilePath, _outputFilePath);
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                              Abstract methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the current output file name
    function _getOutputFileName() internal view virtual returns (string memory);

    /* -------------------------------------------------------------------------- */
    /*                               Utility methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Only execute the method if json write is enabled
    modifier _onlyIfJsonWriteEnabled() {
        if (_isWriteEnabled) {
            _;
        }
    }

    /// @dev Add benchmark result to the json and log it
    function _addResult(string memory _key, string memory _testCase, uint256 _gasUsed)
        internal
        _onlyIfJsonWriteEnabled
    {
        // Build the json key path of the result
        string memory keyPath = string.concat(".", _key, ".", _testCase);

        // Add it to the json
        vm.writeJson(LibString.toString(_gasUsed), _outputFilePath, keyPath);
    }
}
