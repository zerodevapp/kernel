// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {Install} from "src/types/Structs.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {CALLTYPE_SINGLE, MODULE_TYPE_VALIDATOR, MODULE_TYPE_FALLBACK} from "src/types/Constants.sol";

/// @title Gas Benchmark Tests
/// @notice Focused gas benchmarks for specific optimization paths
contract GasBenchmarkTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    Kernel kernel;
    MockValidator validator;
    MockFallback mockFallback;

    function setUp() public {
        ep = EntryPointLib.deploy();

        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        validator = new MockValidator();
        mockFallback = new MockFallback();

        // Deploy kernel via factory
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(validator), moduleData: "", internalData: hex""
        });
        kernel = Kernel(payable(factory.deploy(packages, 0)));
        vm.deal(address(kernel), 10 ether);

        vm.startPrank(address(ep));

        // internalData format: selector(4) + callType(1)
        bytes memory internalData = abi.encodePacked(MockFallback.fallbackFunction.selector, CALLTYPE_SINGLE);
        kernel.installModule(MODULE_TYPE_FALLBACK, address(mockFallback), abi.encode(hex"", internalData));
        vm.stopPrank();
    }

    /// @notice Benchmark: nonce() getter exercises _moduleStorage() caching path
    function test_gasBenchmark_nonceGetter() public {
        uint256 gasBefore = gasleft();
        kernel.nonce(0);
        uint256 gasAfter = gasleft();
        emit log_named_uint("Gas used for nonce()", gasBefore - gasAfter);
    }

    /// @notice Benchmark: setNonce exercises _setNonce -> _moduleStorage() caching
    function test_gasBenchmark_setNonce() public {
        vm.startPrank(address(ep));
        uint256 gasBefore = gasleft();
        kernel.setNonce(0, 1);
        uint256 gasAfter = gasleft();
        emit log_named_uint("Gas used for setNonce()", gasBefore - gasAfter);
        vm.stopPrank();
    }

    /// @notice Benchmark: setValidNonceFrom exercises _setValidNonceFrom -> _moduleStorage()
    function test_gasBenchmark_setValidNonceFrom() public {
        vm.startPrank(address(ep));
        uint256 gasBefore = gasleft();
        kernel.setValidNonceFrom(1);
        uint256 gasAfter = gasleft();
        emit log_named_uint("Gas used for setValidNonceFrom()", gasBefore - gasAfter);
        vm.stopPrank();
    }

    /// @notice Benchmark: installed fallback routing
    function test_gasBenchmark_fallback() public {
        uint256 gasBefore = gasleft();
        MockFallback(address(kernel)).fallbackFunction(5);
        uint256 gasAfter = gasleft();
        emit log_named_uint("Gas used for fallback", gasBefore - gasAfter);
    }
}
