pragma solidity ^0.8.0;

import "src/common/Types.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";

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
    Rejected,
    Executed
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

contract WeightedECDSAValidator is EIP712 {
    mapping(address kernel => WeightedECDSAValidatorStorage) public weightedStorage;
    mapping(address guardian => mapping(address kernel => GuardianStorage)) public guardian;
    mapping(bytes32 callDataHash => mapping(address kernel => ProposalStorage)) public proposalStatus;
    mapping(bytes32 callDataHash => mapping(address guardian => mapping(address kernel => VoteStorage))) public
        voteStatus;

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSAValidator", "1");
    }

    function enable(bytes calldata _data) external {
        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold, uint48 _delay) =
            abi.decode(_data, (address[], uint24[], uint24, uint48));
        require(_guardians.length == _weights.length, "Length mismatch");
        require(weightedStorage[msg.sender].totalWeight == 0, "Already enabled");
        weightedStorage[msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][msg.sender].weight == 0, "Guardian already enabled");
            guardian[_guardians[i]][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[msg.sender].firstGuardian});
            weightedStorage[msg.sender].firstGuardian = _guardians[i];
            weightedStorage[msg.sender].totalWeight += _weights[i];
        }
        weightedStorage[msg.sender].delay = _delay;
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function approve(bytes32 _callDataHash, address _kernel) external {
        require(guardian[msg.sender][_kernel].weight != 0, "Guardian not enabled");
        ProposalStorage storage proposal = proposalStatus[_callDataHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        VoteStorage storage vote = voteStatus[_callDataHash][msg.sender][_kernel];
        require(vote.status == VoteStatus.NA, "Already voted");
        vote.status = VoteStatus.Approved;
        proposal.weightApproved += guardian[msg.sender][_kernel].weight;
        if (proposal.weightApproved >= weightedStorage[_kernel].threshold) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function approveWithSig(bytes32 _callDataHash, address _kernel, bytes calldata sigs) external {
        uint256 sigCount = sigs.length / 65;
        ProposalStorage storage proposal = proposalStatus[_callDataHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        for (uint256 i = 0; i < sigCount; i++) {
            address signer = ECDSA.recover(
                _hashTypedData(keccak256(abi.encode(keccak256("Approve(bytes32 calldataHash)"), _callDataHash))),
                sigs[i * 65:(i + 1) * 65]
            );
            VoteStorage storage vote = voteStatus[_callDataHash][signer][_kernel];
            require(vote.status == VoteStatus.NA, "Already voted");
            vote.status = VoteStatus.Approved;
            proposal.weightApproved += guardian[signer][_kernel].weight;
        }
        if (proposal.weightApproved >= weightedStorage[_kernel].threshold) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function veto(bytes32 _callDataHash) external {
        ProposalStorage storage proposal = proposalStatus[_callDataHash][msg.sender];
        require(
            proposal.status == ProposalStatus.Ongoing || proposal.status == ProposalStatus.Approved,
            "Proposal not ongoing"
        );
        proposal.status = ProposalStatus.Rejected;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        payable
        returns (ValidationData validationData)
    {
        bytes32 callDataHash = keccak256(userOp.callData);
        ProposalStorage storage proposal = proposalStatus[callDataHash][msg.sender];
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
            address signer;
            VoteStorage storage vote;
            for (uint256 i = 0; i < sigCount - 1; i++) {
                // last sig is for userOpHash verification
                signer = ECDSA.recover(
                    _hashTypedData(keccak256(abi.encode(keccak256("Approve(bytes32 calldataHash)"), callDataHash))),
                    sig[i * 65:(i + 1) * 65]
                );
                vote = voteStatus[callDataHash][signer][msg.sender];
                if (vote.status != VoteStatus.NA) {
                    continue;
                } // skip if already voted
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
            }
            // use userOpHash signer's signature
            signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), sig[sig.length - 65:]);
            vote = voteStatus[callDataHash][signer][msg.sender];
            if (vote.status == VoteStatus.NA) {
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
            }
            if (totalWeight >= strg.threshold) {
                proposal.status = ProposalStatus.Approved;
                validationData = packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0));
                proposal.status = ProposalStatus.Executed;
            } else {
                validationData = SIG_VALIDATION_FAILED;
            }
        } else if (proposal.status == ProposalStatus.Approved) {
            validationData = packValidationData(proposal.validAfter, ValidUntil.wrap(0));
            address userOpSigner = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature);
            if (guardian[userOpSigner][msg.sender].weight == 0) {
                return SIG_VALIDATION_FAILED;
            }
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }
}
