// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Lib4337} from "src/lib/Lib4337.sol";

/// @notice Thin external wrapper around Lib4337.chainAgnosticUserOpHash so that
///         tests can pass PackedUserOperation memory structs (the external call
///         boundary provides the automatic memory→calldata conversion).
contract ChainAgnosticHashHelper {
    function chainAgnosticUserOpHash(address ep, PackedUserOperation calldata userOp) external view returns (bytes32) {
        return Lib4337.chainAgnosticUserOpHash(ep, userOp);
    }
}
