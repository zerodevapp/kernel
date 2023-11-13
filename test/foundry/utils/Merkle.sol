pragma solidity ^0.8.0;

function _getRoot(bytes32[] memory data) pure returns (bytes32) {
    require(data.length > 1);
    while (data.length > 1) {
        data = _hashLevel(data);
    }
    return data[0];
}

function _getProof(bytes32[] memory data, uint256 nodeIndex, bool wrongProof) pure returns (bytes32[] memory) {
    require(data.length > 1);

    bytes32[] memory result = new bytes32[](64);
    uint256 pos;

    while (data.length > 1) {
        unchecked {
            if (nodeIndex & 0x1 == 1) {
                result[pos] = data[nodeIndex - 1];
            } else if (nodeIndex + 1 == data.length) {
                result[pos] = bytes32(0);
            } else {
                result[pos] = data[nodeIndex + 1];
            }
            ++pos;
            nodeIndex /= 2;
        }
        data = _hashLevel(data);
    }
    // Resize the length of the array to fit.
    /// @solidity memory-safe-assembly
    assembly {
        mstore(result, pos)
    }
    if (wrongProof) {
        result[0] = result[0] ^ bytes32(uint256(0x01));
    }

    return result;
}

function _hashLevel(bytes32[] memory data) pure returns (bytes32[] memory) {
    bytes32[] memory result;
    unchecked {
        uint256 length = data.length;
        if (length & 0x1 == 1) {
            result = new bytes32[](length / 2 + 1);
            result[result.length - 1] = _hashPair(data[length - 1], bytes32(0));
        } else {
            result = new bytes32[](length / 2);
        }
        uint256 pos = 0;
        for (uint256 i = 0; i < length - 1; i += 2) {
            result[pos] = _hashPair(data[i], data[i + 1]);
            ++pos;
        }
    }
    return result;
}

function _hashPair(bytes32 left, bytes32 right) pure returns (bytes32 result) {
    /// @solidity memory-safe-assembly
    assembly {
        switch lt(left, right)
        case 0 {
            mstore(0x0, right)
            mstore(0x20, left)
        }
        default {
            mstore(0x0, left)
            mstore(0x20, right)
        }
        result := keccak256(0x0, 0x40)
    }
}
