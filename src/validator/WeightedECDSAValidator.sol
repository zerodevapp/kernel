pragma solidity ^0.8.0;

import "src/common/Types.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

struct WeightedECDSAValidatorStorage {
    uint24 totalWeight;
    uint24 threshold;
    uint48 delay;
    address firstGuardian;
}

struct GuardianStorage {
    uint24 weight;
    address nextGuardian;
}

enum ProposalStatus {
    Ongoing, // all proposal is ongoing by default
    Approved,
    Rejected
}

struct ProposalStorage {
    ProposalStatus status;
    ValidAfter validAfter;
    uint24 weightApproved;
}

enum VoteStatus {
    NA,
    Approved
}

struct VoteStorage {
    VoteStatus status;
}

contract WeightedECDSAValidator {
    mapping(address kernel => WeightedECDSAValidatorStorage) public weightedStorage;
    mapping(address guardian => mapping(address kernel => GuardianStorage)) public guardian;
    mapping(bytes32 userOpHash => mapping(address kernel => ProposalStorage)) public proposalStatus;
    mapping(bytes32 userOpHash => mapping(address guardian => mapping(address kernel => VoteStorage))) public voteStatus;

    function enable(bytes calldata _data) external {
        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold, uint48 _delay) =
            abi.decode(_data, (address[], uint24[], uint24, uint48));
        require(_guardians.length == _weights.length, "Length mismatch");
        require(weightedStorage[msg.sender].totalWeight == 0, "Already enabled");
        weightedStorage[msg.sender].firstGuardian = msg.sender;
        for(uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][msg.sender].weight == 0, "Guardian already enabled");
            guardian[_guardians[i]][msg.sender] = GuardianStorage({
                weight: _weights[i],
                nextGuardian: weightedStorage[msg.sender].firstGuardian
            });
            weightedStorage[msg.sender].firstGuardian = _guardians[i];
            weightedStorage[msg.sender].totalWeight += _weights[i];
        }
        weightedStorage[msg.sender].delay = _delay;
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function approve(bytes32 _userOpHash, address _kernel) external {
        require(guardian[msg.sender][_kernel].weight != 0, "Guardian not enabled");
        ProposalStorage storage proposal = proposalStatus[_userOpHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        VoteStorage storage vote = voteStatus[_userOpHash][msg.sender][_kernel];
        require(vote.status == VoteStatus.NA, "Already voted");
        vote.status = VoteStatus.Approved;
        proposal.weightApproved += guardian[msg.sender][_kernel].weight;
        if (proposal.weightApproved >= weightedStorage[_kernel].threshold) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function approveWithSig(bytes32 _userOpHash, address _kernel, bytes calldata sigs) external {
        uint256 sigCount = sigs.length / 65;
        ProposalStorage storage proposal = proposalStatus[_userOpHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        for (uint256 i = 0; i < sigCount; i++) {
            address signer = ECDSA.recover(_userOpHash, sigs[i * 65:(i + 1) * 65]);
            VoteStorage storage vote = voteStatus[_userOpHash][signer][_kernel];
            require(vote.status == VoteStatus.NA, "Already voted");
            vote.status = VoteStatus.Approved;
            proposal.weightApproved += guardian[signer][_kernel].weight;
        }
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
            uint256 totalWeight = proposal.weightApproved;
            for (uint256 i = 0; i < sigCount; i++) {
                address signer = ECDSA.recover(userOpHash, sig[i * 65:(i + 1) * 65]);
                VoteStorage storage vote = voteStatus[userOpHash][signer][msg.sender];
                require(vote.status == VoteStatus.NA, "Already voted");
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
            }
            if (totalWeight >= strg.threshold) {
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
