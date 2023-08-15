pragma solidity ^0.8.0;


library Create2Flag {
    function on(bytes32 key) internal {
        bytes memory code = hex"3859818153F3";
        assembly {
            pop(create2(0, add(code, 0x20), mload(code), key)) // don't deal with the addresses now
        }
    }

    function isOff(bytes32 key) internal view returns(bool off) {
        address addr = getFlagAddress(key);
        assembly {
            off := iszero(extcodesize(addr))
        }
    }

    function getFlagAddress(
        bytes32 _salt
    ) internal view returns (address) {
        bytes memory code = hex"3859818153F3";
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(code))
        );
        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint(hash)));
    }
}
