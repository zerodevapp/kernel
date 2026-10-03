// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {MODULE_TYPE_EXECUTOR} from "src/types/Constants.sol";
import {ModuleInstallFailed, Unauthorized} from "src/types/Error.sol";
import {Install} from "src/types/Structs.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";

/// @dev Stateful executor whose failed cleanup leaves the previous signer in module storage.
contract LifecycleExecutor is IExecutor {
    error InstallRejected();
    error UninstallRejected();
    error WrongSigner();

    mapping(address => address) public signer;
    bool public rejectInstall;
    bool public rejectUninstall;

    function setCallbackFailures(bool installFails, bool uninstallFails) external {
        rejectInstall = installFails;
        rejectUninstall = uninstallFails;
    }

    function onInstall(bytes calldata data) external payable override {
        require(!rejectInstall, InstallRejected());
        signer[msg.sender] = abi.decode(data, (address));
    }

    function onUninstall(bytes calldata) external payable override {
        require(!rejectUninstall, UninstallRejected());
        delete signer[msg.sender];
    }

    function execute(Kernel account, address recipient) external {
        require(msg.sender == signer[address(account)], WrongSigner());
        account.executeFromExecutor(bytes32(0), abi.encodePacked(recipient, uint256(1 ether)));
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return signer[account] != address(0);
    }
}

/// @notice TOB-KERNEL-11: failed reinstallation must not reactivate stale executor authorization.
contract ExecutorReinstallationTest is Test {
    IEntryPoint ep;
    Kernel kernel;
    LifecycleExecutor executor;
    address oldSigner;
    address newSigner;
    address recipient;

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);
        address owner = makeAddr("Owner");
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(owner));
        vm.deal(owner, 10 ether);

        oldSigner = makeAddr("Old signer");
        newSigner = makeAddr("New signer");
        recipient = makeAddr("Recipient");
        executor = new LifecycleExecutor();

        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(abi.encode(oldSigner), hex""));

        // Positive control: the old signer can spend before revocation.
        vm.prank(oldSigner);
        executor.execute(kernel, recipient);
        assertEq(recipient.balance, 1 ether);
    }

    function test_FailedCleanupAndFailedReinstallationKeepOldSignerRevoked() external {
        _uninstall(true);
        assertEq(executor.signer(address(kernel)), oldSigner, "failed cleanup preserves the old signer");
        _assertFailedReinstallation();

        // The executor still accepts this signer, but Kernel must reject the executor.
        vm.prank(oldSigner);
        vm.expectRevert(Unauthorized.selector);
        executor.execute(kernel, recipient);
        assertEq(recipient.balance, 1 ether, "stale authorization must not spend after reinstallation fails");
    }

    function test_SuccessfulCleanupAndFailedReinstallationKeepExecutorRevoked() external {
        _uninstall(false);
        _assertFailedReinstallation();
        assertEq(executor.signer(address(kernel)), address(0), "failed installation must not set a new signer");

        vm.prank(address(executor));
        vm.expectRevert(Unauthorized.selector);
        kernel.executeFromExecutor(bytes32(0), abi.encodePacked(recipient, uint256(1 ether)));
        assertEq(recipient.balance, 1 ether);
    }

    function test_FailedCleanupAndSuccessfulReinstallationReplaceOldSigner() external {
        _uninstall(true);
        _assertSuccessfulReinstallation();
    }

    function test_SuccessfulCleanupAndSuccessfulReinstallationReplaceOldSigner() external {
        _uninstall(false);
        _assertSuccessfulReinstallation();
    }

    function test_FailedReinstallationRollsBackEarlierBatchInstall() external {
        _uninstall(true);
        executor.setCallbackFailures(true, false);
        LifecycleExecutor freshExecutor = new LifecycleExecutor();
        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: MODULE_TYPE_EXECUTOR,
            module: address(freshExecutor),
            moduleData: abi.encode(newSigner),
            internalData: hex""
        });
        packages[1] = Install({
            moduleType: MODULE_TYPE_EXECUTOR,
            module: address(executor),
            moduleData: abi.encode(newSigner),
            internalData: hex""
        });

        vm.prank(address(ep));
        vm.expectRevert(ModuleInstallFailed.selector);
        kernel.installModule(packages);

        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), hex""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(freshExecutor), hex""));
        assertEq(freshExecutor.signer(address(kernel)), address(0), "earlier callback state must also roll back");
        assertEq(executor.signer(address(kernel)), oldSigner);
        vm.prank(oldSigner);
        vm.expectRevert(Unauthorized.selector);
        executor.execute(kernel, recipient);
        assertEq(recipient.balance, 1 ether);
    }

    function _uninstall(bool cleanupFails) internal {
        executor.setCallbackFailures(false, cleanupFails);
        vm.prank(address(ep));
        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), hex""));
        assertEq(executor.signer(address(kernel)), cleanupFails ? oldSigner : address(0));
    }

    function _assertFailedReinstallation() internal {
        executor.setCallbackFailures(true, false);
        vm.prank(address(ep));
        vm.expectRevert(ModuleInstallFailed.selector);
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(abi.encode(newSigner), hex""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), hex""));
    }

    function _assertSuccessfulReinstallation() internal {
        executor.setCallbackFailures(false, false);
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(abi.encode(newSigner), hex""));
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), hex""));
        assertEq(executor.signer(address(kernel)), newSigner);

        vm.prank(oldSigner);
        vm.expectRevert(LifecycleExecutor.WrongSigner.selector);
        executor.execute(kernel, recipient);
        assertEq(recipient.balance, 1 ether);

        vm.prank(newSigner);
        executor.execute(kernel, recipient);
        assertEq(recipient.balance, 2 ether, "the replacement signer should be able to spend");
    }
}
