// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "./Kernel.sol";
import {Install} from "./types/Structs.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady/utils/Initializable.sol";

/// @title KernelUUPS
/// @author taek <leekt216@gmail.com>
/// @notice UUPS-upgradeable Kernel smart account implementation.
/// @dev Uses Solady's Initializable guard; the constructor disables initializers on the implementation.
contract KernelUUPS is Kernel, UUPSUpgradeable, Initializable {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {
        _disableInitializers();
    }

    /// @notice Initializes the Kernel account with the given module packages.
    /// @dev Can only be called once via the `initializer` modifier.
    /// @param packages The module install packages; the first becomes the root validator.
    function initialize(Install[] calldata packages) external payable override initializer {
        _initialize(packages);
    }

    /// @notice Authorization check for UUPS upgrades; only entry point or self can upgrade.
    function _authorizeUpgrade(address) internal view override {
        _onlyEntryPointOrSelf();
    }
}
