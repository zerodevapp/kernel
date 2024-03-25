pragma solidity ^0.8.0;

import "src/types/Types.sol";
import {ECDSA} from "solady/src/utils/ECDSA.sol";
import {EIP712} from "solady/src/utils/EIP712.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    IValidator, VALIDATION_FAILED, MODULE_TYPE_VALIDATOR, MODULE_TYPE_HOOK
} from "../interfaces/IERC7579Modules.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "../types/Constants.sol";

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
}

enum VoteStatus {
    NA,
    Approved
}

struct VoteStorage {
    VoteStatus status;
}

contract WeightedECDSAValidator is EIP712, IValidator {
    mapping(address kernel => WeightedECDSAValidatorStorage) public weightedStorage;
    mapping(address guardian => mapping(address kernel => GuardianStorage)) public guardian;
    mapping(bytes32 callDataAndNonceHash => mapping(address kernel => ProposalStorage)) public proposalStatus;
    mapping(bytes32 callDataAndNonceHash => mapping(address guardian => mapping(address kernel => VoteStorage))) public
        voteStatus;

    event GuardianAdded(address indexed guardian, address indexed kernel, uint24 weight);
    event GuardianRemoved(address indexed guardian, address indexed kernel);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSAValidator", "0.0.2");
    }

    function onInstall(bytes calldata _data) external payable override {
        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold, uint48 _delay) =
            abi.decode(_data, (address[], uint24[], uint24, uint48));
        require(_guardians.length == _weights.length, "Length mismatch");
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        weightedStorage[msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != msg.sender, "Guardian cannot be self");
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][msg.sender].weight == 0, "Guardian already enabled");
            guardian[_guardians[i]][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[msg.sender].firstGuardian});
            weightedStorage[msg.sender].firstGuardian = _guardians[i];
            weightedStorage[msg.sender].totalWeight += _weights[i];
            emit GuardianAdded(_guardians[i], msg.sender, _weights[i]);
        }
        weightedStorage[msg.sender].delay = _delay;
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address currentGuardian = weightedStorage[msg.sender].firstGuardian;
        while (currentGuardian != msg.sender) {
            address nextGuardian = guardian[currentGuardian][msg.sender].nextGuardian;
            emit GuardianRemoved(currentGuardian, msg.sender);
            delete guardian[currentGuardian][msg.sender];
            currentGuardian = nextGuardian;
        }
        delete weightedStorage[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return weightedStorage[smartAccount].totalWeight != 0;
    }

    function renew(address[] calldata _guardians, uint24[] calldata _weights, uint24 _threshold, uint48 _delay)
        external
        payable
    {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address currentGuardian = weightedStorage[msg.sender].firstGuardian;
        while (currentGuardian != msg.sender) {
            address nextGuardian = guardian[currentGuardian][msg.sender].nextGuardian;
            emit GuardianRemoved(currentGuardian, msg.sender);
            delete guardian[currentGuardian][msg.sender];
            currentGuardian = nextGuardian;
        }
        delete weightedStorage[msg.sender];
        require(_guardians.length == _weights.length, "Length mismatch");
        weightedStorage[msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != msg.sender, "Guardian cannot be self");
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][msg.sender].weight == 0, "Guardian already enabled");
            guardian[_guardians[i]][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[msg.sender].firstGuardian});
            weightedStorage[msg.sender].firstGuardian = _guardians[i];
            weightedStorage[msg.sender].totalWeight += _weights[i];
            emit GuardianAdded(_guardians[i], msg.sender, _weights[i]);
        }
        weightedStorage[msg.sender].delay = _delay;
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function approve(bytes32 _callDataAndNonceHash, address _kernel) external payable {
        require(guardian[msg.sender][_kernel].weight != 0, "Guardian not enabled");
        require(weightedStorage[_kernel].threshold != 0, "Kernel not enabled");
        ProposalStorage storage proposal = proposalStatus[_callDataAndNonceHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        VoteStorage storage vote = voteStatus[_callDataAndNonceHash][msg.sender][_kernel];
        require(vote.status == VoteStatus.NA, "Already voted");
        vote.status = VoteStatus.Approved;
        (, bool isApproved) = getApproval(_kernel, _callDataAndNonceHash);
        if (isApproved) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function approveWithSig(bytes32 _callDataAndNonceHash, address _kernel, bytes calldata sigs) external payable {
        uint256 sigCount = sigs.length / 65;
        require(weightedStorage[_kernel].threshold != 0, "Kernel not enabled");
        ProposalStorage storage proposal = proposalStatus[_callDataAndNonceHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        for (uint256 i = 0; i < sigCount; i++) {
            address signer = ECDSA.recover(
                _hashTypedData(
                    keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), _callDataAndNonceHash))
                ),
                sigs[i * 65:(i + 1) * 65]
            );
            VoteStorage storage vote = voteStatus[_callDataAndNonceHash][signer][_kernel];
            require(vote.status == VoteStatus.NA, "Already voted");
            vote.status = VoteStatus.Approved;
        }

        (, bool isApproved) = getApproval(_kernel, _callDataAndNonceHash);
        if (isApproved) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function veto(bytes32 _callDataAndNonceHash) external payable {
        ProposalStorage storage proposal = proposalStatus[_callDataAndNonceHash][msg.sender];
        require(
            proposal.status == ProposalStatus.Ongoing || proposal.status == ProposalStatus.Approved,
            "Proposal not ongoing"
        );
        proposal.status = ProposalStatus.Rejected;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        bytes32 callDataAndNonceHash = keccak256(abi.encode(userOp.sender, userOp.callData, userOp.nonce));
        ProposalStorage storage proposal = proposalStatus[callDataAndNonceHash][msg.sender];
        WeightedECDSAValidatorStorage storage strg = weightedStorage[msg.sender];
        if (strg.threshold == 0) {
            return VALIDATION_FAILED;
        }
        (uint256 totalWeight, bool passed) = getApproval(msg.sender, callDataAndNonceHash);
        uint256 threshold = strg.threshold;
        if (proposal.status == ProposalStatus.Ongoing && !passed) {
            if (strg.delay != 0) {
                // if delay > 0, only allow proposal to be approved before execution
                return VALIDATION_FAILED;
            }
            bytes calldata sig = userOp.signature;
            // parse sig with 65 bytes
            uint256 sigCount = sig.length / 65;
            require(sigCount > 0, "No sig");
            address signer;
            VoteStorage storage vote;
            for (uint256 i = 0; i < sigCount - 1 && !passed; i++) {
                signer = ECDSA.recover(
                    _hashTypedData(
                        keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), callDataAndNonceHash))
                    ),
                    sig[i * 65:(i + 1) * 65]
                );
                vote = voteStatus[callDataAndNonceHash][signer][msg.sender];
                if (vote.status != VoteStatus.NA) {
                    continue;
                } // skip if already voted
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
                if (totalWeight >= threshold) {
                    passed = true;
                }
            }
            // userOpHash verification for the last sig
            signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), sig[sig.length - 65:]);
            vote = voteStatus[callDataAndNonceHash][signer][msg.sender];
            if (vote.status == VoteStatus.NA) {
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
                if (totalWeight >= threshold) {
                    passed = true;
                }
            }
            if (passed && guardian[signer][msg.sender].weight != 0) {
                proposal.status = ProposalStatus.Executed;
                return packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0));
            }
        } else if (proposal.status == ProposalStatus.Approved || passed) {
            address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature);
            if (guardian[signer][msg.sender].weight != 0) {
                proposal.status = ProposalStatus.Executed;
                return packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0));
            }
        }
        return VALIDATION_FAILED;
    }

    function getApproval(address kernel, bytes32 hash) public view returns (uint256 approvals, bool passed) {
        WeightedECDSAValidatorStorage storage strg = weightedStorage[kernel];
        for (
            address currentGuardian = strg.firstGuardian;
            currentGuardian != address(0);
            currentGuardian = guardian[currentGuardian][kernel].nextGuardian
        ) {
            if (voteStatus[hash][currentGuardian][kernel].status == VoteStatus.Approved) {
                approvals += guardian[currentGuardian][kernel].weight;
            }
        }
        ProposalStorage storage proposal = proposalStatus[hash][kernel];
        if (proposal.status == ProposalStatus.Rejected) {
            passed = false;
        } else {
            passed = approvals >= strg.threshold;
        }
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4)
    {
        WeightedECDSAValidatorStorage storage strg = weightedStorage[msg.sender];
        if (strg.threshold == 0) {
            return ERC1271_INVALID;
        }

        uint256 sigCount = data.length / 65;
        if (sigCount == 0) {
            return ERC1271_INVALID;
        }
        uint256 totalWeight = 0;
        address signer;
        for (uint256 i = 0; i < sigCount; i++) {
            signer = ECDSA.recover(hash, data[i * 65:(i + 1) * 65]);
            totalWeight += guardian[signer][msg.sender].weight;
            if (totalWeight >= strg.threshold) {
                return ERC1271_MAGICVALUE;
            }
        }
        return ERC1271_INVALID;
    }
}
