pragma solidity ^0.8.0;

import {MockHook} from "./mock/MockHook.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

abstract contract KernelHookTest is KernelTestBase {
    function test_install_hook() external unitTest {
        assertTrue(kernel.supportsModule(4));
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        assertTrue(kernel.isModuleInstalled(4, address(mockHook), hex""));
    }

    function test_uninstall_hook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.uninstallModule(4, address(mockHook), abi.encode(hex"", ""));
    }
}
