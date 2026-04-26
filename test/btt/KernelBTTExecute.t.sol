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
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {PermissionId} from "src/types/Types.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";

// Import BTT test contract
import {Kernel_execute} from "./Kernel.execute.t.sol";

/// @title Kernel BTT Execute Concrete Tests
contract KernelBTT_Execute_Test is Kernel_execute {
    function setUp() public {
        _initialize();
    }

    function _initialize() internal override {
        // Deploy EntryPoint
        ep = EntryPointLib.deploy();

        // Deploy Kernel implementation and factory
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);

        // Set up mock contracts
        MockValidator mockValidator = new MockValidator();
        mockValidator.sudoSetSuccess(true);
        rootValidator = IValidator(address(mockValidator));
        rootValidatorData = hex"";

        newValidator = new MockValidator();
        newValidator.sudoSetSuccess(true);

        policy = new MockPolicy();
        signer = new MockSigner();
        hook = new MockHook();
        mockFallback = new MockFallback();
        callee = new MockCallee();

        MockExecutor mockExecutor = new MockExecutor();
        executor = address(mockExecutor);

        beneficiary = payable(makeAddr("beneficiary"));
        permissionId = PermissionId.wrap(bytes4(keccak256("testPermission")));

        // Deploy kernel with root validator
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});

        kernel = Kernel(payable(factory.deploy(packages, 0)));

        // Fund kernel
        vm.deal(address(kernel), 100 ether);

        // Set flags
        isMock = true;
        is7702 = false;
        isImmutable = false;
    }
}
