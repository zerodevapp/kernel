pragma solidity ^0.8.0;

import "src/common/Types.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

struct WeightedECDSAValidatorStorage {
    uint64 totalWeight;
    uint64 threshold;
    uint48 delay;
}

enum ProposalStatus {
    Ongoing, // all proposal is ongoing by default
    Approved,
    Rejected
}

struct ProposalStorage {
    ProposalStatus status;
    ValidAfter validAfter;
    uint64 weightApproved;
}

contract WeightedECDSAValidator {
    mapping(address kernel => WeightedECDSAValidatorStorage) public weightedStorage;
    mapping(address guardian => mapping(address kernel => uint64)) public weights;
    mapping(bytes32 userOpHash => mapping(address kernel => ProposalStorage)) public proposalStatus;

    function enable(bytes calldata _data) external {
        (address[] memory _guardians, uint64[] memory _weights, uint256 _threshold, uint256 _delay) =
            abi.decode(_data, (address[], uint64[], uint256, uint256));
        require(_guardians.length == _weights.length, "Length mismatch");
        uint256 totalWeight = 0;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_weights[i] != 0, "Weight must be positive");
            require(weights[_guardians[i]][msg.sender] == 0, "Guardian already enabled");
            totalWeight += _weights[i];
            weights[_guardians[i]][msg.sender] = _weights[i];
        }
        weightedStorage[msg.sender] = WeightedECDSAValidatorStorage({
            totalWeight: uint64(totalWeight),
            threshold: uint64(_threshold),
            delay: uint48(_delay)
        });
    }

    function approve(bytes32 _userOpHash, address _kernel) external {
        require(weights[msg.sender][_kernel] != 0, "Guardian not enabled");
        ProposalStorage storage proposal = proposalStatus[_userOpHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        proposal.weightApproved += weights[msg.sender][_kernel];
        if (proposal.weightApproved >= weightedStorage[_kernel].threshold) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function approveWithSig(bytes32 _userOpHash, address _kernel, bytes calldata sig) external {
        address guardian = ECDSA.recover(_userOpHash, sig);
        require(weights[guardian][_kernel] != 0, "Guardian not enabled");
        ProposalStorage storage proposal = proposalStatus[_userOpHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        proposal.weightApproved += weights[guardian][_kernel];
        if (proposal.weightApproved >= weightedStorage[_kernel].threshold) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function veto(bytes32 _userOpHash) external {
        ProposalStorage storage proposal = proposalStatus[_userOpHash][msg.sender];
        require(
            proposal.status == ProposalStatus.Ongoing || proposal.status == ProposalStatus.Approved,
            "Proposal not ongoing"
        );
        proposal.status = ProposalStatus.Rejected;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        payable
        returns (ValidationData)
    {
        ProposalStorage storage proposal = proposalStatus[userOpHash][msg.sender];
        WeightedECDSAValidatorStorage storage strg = weightedStorage[msg.sender];
        if (proposal.status == ProposalStatus.Ongoing) {
            if (strg.delay != 0) {
                // if delay > 0, only allow proposal to be approved before execution
                return SIG_VALIDATION_FAILED;
            }
            bytes calldata sig = userOp.signature;
            // parse sig with 65 bytes
            uint256 sigCount = sig.length / 65;
            for (uint256 i = 0; i < sigCount; i++) {
                address guardian = ECDSA.recover(userOpHash, sig[i * 65:(i + 1) * 65]);
                proposal.weightApproved += weights[guardian][msg.sender];
            }
            if (proposal.weightApproved >= strg.threshold) {
                proposal.status = ProposalStatus.Approved;
                return packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0));
            } else {
                return SIG_VALIDATION_FAILED;
            }
        } else if (proposal.status == ProposalStatus.Approved) {
            return packValidationData(proposal.validAfter, ValidUntil.wrap(0));
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }
}
