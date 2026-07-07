// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "./Kernel.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {Install} from "./types/Structs.sol";

/// @title Kernel7702
/// @author taek <leekt216@gmail.com>
/// @notice EIP-7702 variant of Kernel that uses the EOA's own address as the fallback signer.
/// @dev Initialize is a no-op since the EOA delegates its code via EIP-7702.
///      The fallback signature verifies against address(this), which is the EOA itself.
contract Kernel7702 is Kernel {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {}

    /// @notice No-op initializer for EIP-7702 accounts (no initialization needed).
    function initialize(Install[] calldata) external payable override {} // NO-OP

    /// @notice Verifies a fallback signature using ECDSA recovery against address(this).
    function _verifyFallbackSignature(bytes32 hash, bytes calldata sig) internal view override returns (bool) {
        return ECDSA.tryRecoverCalldata(hash, sig) == address(this);
    }

    /// @notice Returns true since EIP-7702 always has a fallback validator (the EOA itself).
    function _fallbackValidatorAvailable() internal pure override returns (bool) {
        return true;
    }

    /// @notice Returns true to allow raw ERC-1271 signatures without nested EIP-712 wrapping.
    function _erc1271RawAllowed() internal pure override returns (bool) {
        return true;
    }
}
