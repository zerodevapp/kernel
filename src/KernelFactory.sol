pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {KernelImmutableECDSA} from "./KernelImmutableECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract KernelFactory {
    KernelUUPS public immutable UUPS;
    KernelImmutableECDSA public immutable IMMUTABLE_ECDSA;

    constructor(KernelUUPS _uups, KernelImmutableECDSA _immutableEcdsa) {
        UUPS = _uups;
        IMMUTABLE_ECDSA = _immutableEcdsa;
    }

    function checkInitialized(address account, bytes calldata initData) external view returns (bool) {
        bytes4 selector = bytes4(initData[0:4]);
        ( /*replayable*/ , /*nonce*/, Install[] memory packages, /*sig*/ ) =
            abi.decode(initData, (bool, uint256, Install[], bytes));

        // naively check if the package has been installed, does not guarantee if proper internalData is used
        for (uint256 i = 0; i < packages.length; i++) {
            Install memory p = packages[i];

            bytes memory context;
            if (p.moduleType == 5 || p.moduleType == 6) {
                context = abi.encodePacked(bytes20(p.internalData));
            }

            if (!Kernel(payable(account)).isModuleInstalled(p.moduleType, p.module, context)) {
                return false;
            }
        }
        return true;
    }

    // Kernel UUPS
    function deploy(Install[] calldata initialPackages, uint256 nonce) external payable returns (Kernel) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(UUPS), salt);
        Kernel k = Kernel(payable(account));
        if (deployed) {
            return k;
        }
        k.initialize(initialPackages);
        return k;
    }

    function deployWithCall(Install[] calldata initialPackages, uint256 nonce, bytes calldata extraCall)
        external
        payable
        returns (Kernel)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(UUPS), salt);
        Kernel k = Kernel(payable(account));
        if (!deployed) {
            k.initialize(initialPackages);
        }
        (bool success,) = address(k).call(extraCall);
        require(success, "call failed");
        return k;
    }

    function getAddress(Install[] calldata initialPackages, uint256 nonce) public view virtual returns (address) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        return LibClone.predictDeterministicAddressERC1967(address(UUPS), salt, address(this));
    }

    // Kernel UUPS ECDSA fallback
    /// forge-lint: disable-next-line(mixed-case-function)
    function deployECDSA(address signer, Install[] calldata initialPackages, uint256 nonce)
        external
        payable
        returns (Kernel)
    {
        require(signer != address(0), InvalidSigner());
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (, address account) =
            LibClone.createDeterministicERC1967(address(IMMUTABLE_ECDSA), abi.encodePacked(signer), salt);
        Kernel k = Kernel(payable(account));
        k.initialize(initialPackages);
        return k;
    }

    /// forge-lint: disable-next-line(mixed-case-function)
    function deployECDSAWithCall(
        address signer,
        Install[] calldata initialPackages,
        uint256 nonce,
        bytes calldata extraCall
    ) external payable returns (Kernel) {
        require(signer != address(0), InvalidSigner());
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (, address account) =
            LibClone.createDeterministicERC1967(address(IMMUTABLE_ECDSA), abi.encodePacked(signer), salt);
        Kernel k = Kernel(payable(account));
        k.initialize(initialPackages);
        (bool success,) = address(k).call(extraCall);
        require(success, "call failed");
        return k;
    }

    /// forge-lint: disable-next-line(mixed-case-function)
    function getECDSAAddress(address signer, Install[] calldata initialPackages, uint256 nonce)
        public
        view
        virtual
        returns (address)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        return LibClone.predictDeterministicAddressERC1967(
            address(IMMUTABLE_ECDSA), abi.encodePacked(signer), salt, address(this)
        );
    }
}
