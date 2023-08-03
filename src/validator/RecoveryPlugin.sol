// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";

struct RecoveryPluginStorage {
    address owner;
}

struct Guardian {
    address guardian;
    uint256 weight;
    bool approved;
}

contract RecoveryPlugin is IKernelValidator {
    event OwnerChanged(
        address indexed kernel,
        address indexed oldOwner,
        address indexed newOwner
    );
    event GuardianAdded(
        address indexed kernel,
        Guardian[] guardians,
        uint256 weight
    );

    mapping(address => RecoveryPluginStorage) public recoveryPluginStorage;
    mapping(address => Guardian[]) public guardians;
    mapping(address => uint256) public thresholdWeight;
    mapping(address => uint256) public recoveryDelay;

    function disable(bytes calldata) external override {
        delete recoveryPluginStorage[msg.sender];
    }

    function enable(bytes calldata _data) external override {
        address newOwner = address(bytes20(_data[0:20]));
        bytes32 hash = bytes32(_data[20:52]);
        bytes[] memory signatures = divideBytes(bytes(_data[52:]));
        initRecovery(newOwner, hash, signatures);
    }

    function divideBytes(
        bytes memory data
    ) public pure returns (bytes[] memory) {
        require(data.length % 65 == 0, "Data length must be a multiple of 65");

        uint chunks = data.length / 65;

        bytes[] memory dividedBytes = new bytes[](chunks);

        for (uint i = 0; i < chunks; i++) {
            bytes memory chunk = new bytes(65);
            for (uint j = 0; j < 65; j++) {
                chunk[j] = data[(i * 65) + j];
            }
            dividedBytes[i] = chunk;
        }
        return dividedBytes;
    }

    function changeOwner(address _newOwner) internal {
        address oldOwner = recoveryPluginStorage[msg.sender].owner;
        recoveryPluginStorage[msg.sender].owner = _newOwner;
        for (uint256 i = 0; i < guardians[msg.sender].length; i++) {
            guardians[msg.sender][i].approved = false;
        }
        emit OwnerChanged(msg.sender, oldOwner, _newOwner);
    }

    function addGuardian(
        Guardian[] memory _guardians,
        uint256 _thresholdWeight,
        uint256 delay
    ) public {
        for (uint256 i = 0; i < _guardians.length; i++) {
            if (_guardians[i].weight <= 0) {
                revert();
            }
            if (_guardians[i].guardian == address(0)) {
                revert();
            }
            if (_guardians[i].guardian == msg.sender) {
                revert();
            }
            if (_guardians[i].approved) {
                revert();
            }
            guardians[msg.sender].push(_guardians[i]);
        }
        thresholdWeight[msg.sender] = _thresholdWeight;
        recoveryDelay[msg.sender] = block.timestamp + delay;
        emit GuardianAdded(msg.sender, _guardians, _thresholdWeight);
    }

    function verifyGuardians(
        bytes32 hash,
        bytes[] memory signatures
    ) internal returns (uint256) {
        uint256 weight = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            if (signatures[i].length != 65) {
                revert();
            } else {
                if (
                    validateGuardianSignature(
                        hash,
                        signatures[i],
                        guardians[msg.sender][i].guardian
                    ) ==
                    0 &&
                    !guardians[msg.sender][i].approved
                ) {
                    unchecked {
                        weight += guardians[msg.sender][i].weight;
                    }
                }
            }
        }
        return weight;
    }

    function initRecovery(
        address _newOwner,
        bytes32 hash,
        bytes[] memory signatures
    ) internal {
        address oldOwner = recoveryPluginStorage[msg.sender].owner;
        require(
            _newOwner != address(0),
            "RecoveryPlugin: new owner is zero address"
        );
        require(hash != bytes32(0), "RecoveryPlugin: hash is zero");
        require(
            oldOwner == address(0) ||
                block.timestamp >= recoveryDelay[msg.sender],
            "RecoveryPlugin: recovery delay not reached"
        );
        uint256 weight = verifyGuardians(hash, signatures);
        require(
            weight >= thresholdWeight[msg.sender],
            "RecoveryPlugin: weight is not enough"
        );
        require(
            oldOwner != _newOwner,
            "RecoveryPlugin: new owner is the same as old owner"
        );
        changeOwner(_newOwner);
    }

    function validateUserOp(
        UserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256
    ) external view override returns (uint256 validationData) {
        address owner = recoveryPluginStorage[_userOp.sender].owner;
        if (owner == ECDSA.recover(_userOpHash, _userOp.signature)) {
            return 0;
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        address recovered = ECDSA.recover(hash, _userOp.signature);
        if (owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validateSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (uint256) {
        address owner = recoveryPluginStorage[msg.sender].owner;
        if (owner == ECDSA.recover(hash, signature)) {
            return 0;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.recover(ethHash, signature);
        if (owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    function validateGuardianSignature(
        bytes32 hash,
        bytes memory signature,
        address guardian
    ) public pure returns (uint256) {
        if (guardian == ECDSA.recover(hash, signature)) {
            return 0;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.recover(ethHash, signature);
        if (guardian != recovered) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}
