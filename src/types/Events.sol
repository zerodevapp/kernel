// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Emitted when a module is installed on the account.
/// @param moduleType The module type identifier (1=validator, 2=executor, 3=fallback, 5=policy, 6=signer, 11=scoped execution hook).
/// @param module The address of the installed module.
event ModuleInstalled(uint256 moduleType, address module);

/// @notice Emitted when a module is uninstalled from the account.
/// @param moduleType The module type identifier.
/// @param module The address of the uninstalled module.
event ModuleUninstalled(uint256 moduleType, address module);

/// @notice Emitted when the account receives native ETH via the receive function.
/// @param sender The address that sent the ETH.
/// @param amount The amount of ETH received in wei.
event Received(address sender, uint256 amount);

/// @notice Emitted when a new Kernel account is deployed by the factory.
/// @param kernel The address of the newly deployed Kernel account.
event KernelDeployed(address indexed kernel);

/// @notice Emitted when a factory's approval status changes in the Staker.
/// @param factory The factory address whose approval changed.
/// @param approved True if approved, false if revoked.
event FactoryApprovalChanged(address indexed factory, bool approved);
