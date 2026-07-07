pragma solidity ^0.8.0;

import {IEntryPoint, Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";

// NOTE: this is not for real usecase, just a contract to deploy for test checks
contract MockKernel is Kernel {
    constructor(IEntryPoint ep) Kernel(ep) {}

    function initialize(Install[] calldata packages) external payable override {
        // this is initialize
        // require first package to be the root validator
        _initialize(packages);
    }

    function installDigest(bool replayable, uint256 nonce, Install[] calldata packages)
        external
        view
        returns (bytes32)
    {
        function(bytes32) internal view returns (bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        bytes32 digest = hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "InstallPackages(uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    nonce,
                    _installHash(packages)
                )
            )
        );
        return digest;
    }
}
