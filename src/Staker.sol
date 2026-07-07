// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {APPROVE_FACTORY_STRUCT_HASH} from "./types/Constants.sol";
import {DeployFailed, InvalidOwner, InvalidSignature, NotApprovedFactory} from "./types/Error.sol";
import {FactoryApprovalChanged} from "./types/Events.sol";

/// @title Staker
/// @author taek <leekt216@gmail.com>
/// @notice Manages ERC-4337 entry point staking and approved factory deployments for Kernel accounts.
contract Staker is Ownable, EIP712 {
    mapping(address => bool) public approved;
    mapping(address => uint256) public nonces;

    constructor(address _owner) {
        _initializeOwner(_owner);
    }

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Staker", "0.0.1");
    }

    /// @notice Deploys a Kernel account through an approved factory.
    /// @param factory The factory address; must be pre-approved.
    /// @param createData The calldata to forward to the factory's deploy function.
    /// @return The address of the deployed account.
    function deployWithFactory(address factory, bytes calldata createData) external payable returns (address) {
        require(approved[factory], NotApprovedFactory());
        (bool success, bytes memory ret) = factory.call{value: msg.value}(createData);
        require(success, DeployFailed());
        return abi.decode(ret, (address));
    }

    /// @notice Approves or revokes a factory for deployment (owner only).
    /// @param _factory The factory address to approve or revoke.
    /// @param approval True to approve, false to revoke.
    function approveFactory(address _factory, bool approval) external payable onlyOwner {
        approved[_factory] = approval;
        emit FactoryApprovalChanged(_factory, approval);
    }

    /// @notice Approves or revokes a factory using the owner's off-chain EIP-712 signature.
    /// @dev Uses a chain-agnostic EIP-712 digest. Nonces are tracked per factory address.
    /// @param _factory The factory address to approve or revoke.
    /// @param approval True to approve, false to revoke.
    /// @param signature The owner's ECDSA signature over the typed data digest.
    function approveFactoryWithSignature(address _factory, bool approval, bytes calldata signature) external payable {
        // struct :
        // {
        //   factory: address,
        //   approval: bool,
        //   nonce: uint256,
        // }
        address _owner = owner();
        require(_owner != address(0), InvalidOwner());
        bytes32 digest = _hashTypedDataSansChainId(
            EfficientHashLib.hash(
                uint256(APPROVE_FACTORY_STRUCT_HASH), uint256(uint160(_factory)), approval ? 1 : 0, nonces[_factory]++
            )
        );
        require(_owner == ECDSA.tryRecoverCalldata(digest, signature), InvalidSignature());
        approved[_factory] = approval;
        emit FactoryApprovalChanged(_factory, approval);
    }

    /// @notice Stakes ETH with the ERC-4337 entry point.
    /// @param entryPoint The entry point contract to stake with.
    /// @param unstakeDelay The minimum delay (in seconds) before the stake can be withdrawn.
    function stake(IEntryPoint entryPoint, uint32 unstakeDelay) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelay);
    }

    /// @notice Initiates the unstake delay for the entry point stake.
    /// @param entryPoint The entry point contract to unlock stake from.
    function unlockStake(IEntryPoint entryPoint) external payable onlyOwner {
        entryPoint.unlockStake();
    }

    /// @notice Withdraws the staked ETH from the entry point after the unstake delay.
    /// @param entryPoint The entry point contract to withdraw from.
    /// @param recipient The address to receive the withdrawn stake.
    function withdrawStake(IEntryPoint entryPoint, address payable recipient) external payable onlyOwner {
        entryPoint.withdrawStake(recipient);
    }
}
