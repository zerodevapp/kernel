// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {Install} from "./types/Structs.sol";

/// @title KernelImmutableECDSA
/// @author taek <leekt216@gmail.com>
/// @notice Kernel variant with an immutable ECDSA fallback signer stored in the ERC-1967 clone's immutable args.
/// @dev The signer address is packed into the first 20 bytes of the clone's immutable args.
///      Root validation is NOT set during initialization, allowing the immutable signer to act as fallback.
contract KernelImmutableECDSA is KernelUUPS {
    constructor(IEntryPoint _entryPoint) KernelUUPS(_entryPoint) {}

    /// @notice Verifies a fallback signature against the immutable ECDSA signer.
    function _verifyFallbackSignature(bytes32 hash, bytes calldata sig) internal view override returns (bool) {
        address signer = address(uint160(bytes20(LibClone.argsOnERC1967(address(this), 0, 20))));

        return ECDSA.tryRecoverCalldata(hash, sig) == signer;
    }

    /// @notice Returns true since this variant always has an immutable fallback signer.
    function _fallbackValidatorAvailable() internal pure override returns (bool) {
        return true;
    }

    /// @notice Installs packages without setting root, so the immutable ECDSA signer serves as fallback.
    function _initialize(Install[] calldata packages) internal override {
        _install(packages);
    }
}
