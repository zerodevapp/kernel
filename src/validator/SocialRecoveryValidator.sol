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

contract SocialRecoveryValidator is IKernelValidator {
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
    mapping(address => mapping(address => bool)) public isGuardian;

    function disable(bytes calldata) external override {
        delete recoveryPluginStorage[msg.sender];
    }

    function enable(bytes calldata _data) external override {
        //0x00 - to add guardians
        //0x01 - to change owner
        bytes1 mode = bytes1(_data);
        if (mode == hex"00") {
            bytes32 weightinbytes = bytes32(_data[1:33]);
            uint256 weight = uint256(weightinbytes);
            bytes calldata guardiandata = bytes(_data[33:]);
            addGuardian(guardiandata, weight, 0 days);
        } else if (mode == hex"01") {
            bytes calldata recoverydata = bytes(_data[1:]);
            address newOwner = address(bytes20(recoverydata[0:20]));
            bytes32 hash = bytes32(recoverydata[20:52]);
            bytes[] memory signatures = divideBytes(bytes(recoverydata[52:]));
            initRecovery(newOwner, hash, signatures);
        } else if (mode == hex"02") {
            bytes calldata recoverydata = bytes(_data[1:]);
            address kernelAddress = address(bytes20(recoverydata[0:20]));
            address newOwner = address(bytes20(recoverydata[20:40]));
            bytes32 hash = bytes32(recoverydata[40:72]);
            bytes[] memory signatures = divideBytes(bytes(recoverydata[72:]));
            initRecoveryByGuardian(kernelAddress, newOwner, hash, signatures);
        } else {
            revert("Invalid mode");
        }
    }

    function divideBytes(
        bytes calldata data
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

    function changeOwner(address _newOwner) public {
        address oldOwner = recoveryPluginStorage[msg.sender].owner;
        recoveryPluginStorage[msg.sender].owner = _newOwner;
        for (uint256 i = 0; i < guardians[msg.sender].length; i++) {
            guardians[msg.sender][i].approved = false;
        }
        emit OwnerChanged(msg.sender, oldOwner, _newOwner);
    }

    function changeOwnerByGuardian(
        address kernelAddress,
        address _newOwner
    ) public {
        address oldOwner = recoveryPluginStorage[kernelAddress].owner;
        recoveryPluginStorage[kernelAddress].owner = _newOwner;
        for (uint256 i = 0; i < guardians[kernelAddress].length; i++) {
            guardians[kernelAddress][i].approved = false;
        }
        emit OwnerChanged(kernelAddress, oldOwner, _newOwner);
    }

    function addGuardian(
        bytes calldata _guardiandata,
        uint256 _thresholdWeight,
        uint256 delay
    ) public {
        address extraAddress = address(bytes20(_guardiandata[0:20]));
        recoveryPluginStorage[msg.sender].owner = extraAddress;
        uint256 chunks = _guardiandata.length / 52;
        bytes calldata guardianData = _guardiandata[20:];
        for (uint256 i = 0; i < chunks; i++) {
            address guardian = address(
                bytes20(guardianData[i * 52:(i + 1) * 52])
            );
            require(
                guardian != address(0),
                "RecoveryPlugin: guardian is zero address"
            );
            require(guardian != msg.sender, "RecoveryPlugin: guardian is self");
            uint256 weight = (
                uint256(
                    uint160(
                        bytes20(guardianData[(i + 1) * 52 - 20:(i + 1) * 52])
                    )
                )
            );
            require(weight > 0, "RecoveryPlugin: weight is zero");
            isGuardian[msg.sender][guardian] = true;
            guardians[msg.sender].push(Guardian(guardian, weight, false));
        }
        thresholdWeight[msg.sender] = _thresholdWeight;
        recoveryDelay[msg.sender] = block.timestamp + delay;
        emit GuardianAdded(msg.sender, guardians[msg.sender], _thresholdWeight);
    }

    function getGuardianByIndex(
        address _kernel,
        uint256 _index
    ) public view returns (Guardian memory) {
        return guardians[_kernel][_index];
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

    function initRecoveryByGuardian(
        address kernelAddress,
        address _newOwner,
        bytes32 hash,
        bytes[] memory signatures
    ) public {
        address oldOwner = recoveryPluginStorage[kernelAddress].owner;
        require(
            _newOwner != address(0),
            "RecoveryPlugin: new owner is zero address"
        );
        require(hash != bytes32(0), "RecoveryPlugin: hash is zero");
        require(
            oldOwner == address(0) ||
                block.timestamp >= recoveryDelay[kernelAddress],
            "RecoveryPlugin: recovery delay not reached"
        );
        uint256 weight = verifyGuardians(hash, signatures);
        require(
            weight >= thresholdWeight[kernelAddress],
            "RecoveryPlugin: weight is not enough"
        );
        require(
            oldOwner != _newOwner,
            "RecoveryPlugin: new owner is the same as old owner"
        );
        changeOwnerByGuardian(kernelAddress, _newOwner);
    }

    function initRecovery(
        address _newOwner,
        bytes32 hash,
        bytes[] memory signatures
    ) public {
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

    function _slice(
        bytes memory data,
        uint start
    ) private pure returns (bytes1) {
        require(start < data.length, "Start index out of bounds");

        return bytes1(data[start]);
    }

    function validateUserOp(
        UserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256
    ) external view override returns (uint256 validationData) {
        if (_userOp.callData.length >= 232) {
            bytes1 mode = _slice(_userOp.callData, 232);
            if (mode == bytes1(0x01) || mode == bytes1(0x00)) {
                address owner = recoveryPluginStorage[_userOp.sender].owner;
                if (owner == ECDSA.recover(_userOpHash, _userOp.signature)) {
                    return 0;
                }

                bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
                address recovered = ECDSA.recover(hash, _userOp.signature);
                if (owner != recovered) {
                    return SIG_VALIDATION_FAILED;
                }
            } else if (mode == bytes1(0x02)) {
                address kernelAddress = address(
                    bytes20(_userOp.callData[233:253])
                );
                require(
                    isGuardian[kernelAddress][_userOp.sender],
                    "Recovery Plugin: Not a guardian"
                );
                return 0;
            }
        } else if (_userOp.callData.length < 232) {
            address owner = recoveryPluginStorage[_userOp.sender].owner;
            if (owner == ECDSA.recover(_userOpHash, _userOp.signature)) {
                return 0;
            }

            bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
            address recovered = ECDSA.recover(hash, _userOp.signature);
            if (owner != recovered) {
                return SIG_VALIDATION_FAILED;
            }
        } else {
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
