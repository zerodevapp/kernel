// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import "forge-std/Test.sol";
import "solady/utils/ECDSA.sol";
import "src/Kernel.sol";
import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";

abstract contract KernelTestBase is Test {
    Kernel kernel;
    Kernel kernelImpl;
    KernelFactory factory;
    EntryPoint entryPoint;
    IKernelValidator defaultValidator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;
    address factoryOwner;

    function _initialize() internal {
        (owner, ownerKey) = makeAddrAndKey("owner");
        (factoryOwner,) = makeAddrAndKey("factoryOwner");
        beneficiary = payable(address(makeAddr("beneficiary")));
        entryPoint = new EntryPoint();
        kernelImpl = new Kernel(entryPoint);
        factory = new KernelFactory(factoryOwner, entryPoint);
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();
    }

    function _setAddress() internal {
        kernel = Kernel(
            payable(
                address(
                    factory.createAccount(
                        address(kernelImpl),
                        abi.encodeWithSelector(
                            KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(owner)
                        ),
                        0
                    )
                )
            )
        );
        vm.deal(address(kernel), 1e30);
    }

    function logGas(UserOperation memory op) internal returns (uint256 used) {
        try this.consoleGasUsage(op) {
            revert("should revert");
        } catch Error(string memory reason) {
            used = abi.decode(bytes(reason), (uint256));
            console.log("validation gas usage :", used);
        }
    }

    function consoleGasUsage(UserOperation memory op) external {
        uint256 gas = gasleft();
        vm.startPrank(address(entryPoint));
        kernel.validateUserOp(op, entryPoint.getUserOpHash(op), 0);
        vm.stopPrank();
        revert(string(abi.encodePacked(gas - gasleft())));
    }
}

library ERC4337Utils {
    function fillUserOp(EntryPoint _entryPoint, address _sender, bytes memory _data)
        internal
        view
        returns (UserOperation memory op)
    {
        op.sender = _sender;
        op.nonce = _entryPoint.getNonce(_sender, 0);
        op.callData = _data;
        op.callGasLimit = 10000000;
        op.verificationGasLimit = 10000000;
        op.preVerificationGas = 50000;
        op.maxFeePerGas = 50000;
        op.maxPriorityFeePerGas = 1;
    }

    function signUserOpHash(EntryPoint _entryPoint, Vm _vm, uint256 _key, UserOperation memory _op)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 hash = _entryPoint.getUserOpHash(_op);
        (uint8 v, bytes32 r, bytes32 s) = _vm.sign(_key, ECDSA.toEthSignedMessageHash(hash));
        signature = abi.encodePacked(r, s, v);
    }
}

// computes the hash of a permit
function getStructHash(
    bytes4 sig,
    uint48 validUntil,
    uint48 validAfter,
    address validator,
    address executor,
    bytes memory enableData
) pure returns (bytes32) {
    return keccak256(
        abi.encode(
            keccak256("ValidatorApproved(bytes4 sig,uint256 validatorData,address executor,bytes enableData)"),
            bytes4(sig),
            uint256(uint256(uint160(validator)) | (uint256(validAfter) << 160) | (uint256(validUntil) << (48 + 160))),
            executor,
            keccak256(enableData)
        )
    );
}

// computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
function getTypedDataHash(
    address sender,
    bytes4 sig,
    uint48 validUntil,
    uint48 validAfter,
    address validator,
    address executor,
    bytes memory enableData
) view returns (bytes32) {
    return keccak256(
        abi.encodePacked(
            "\x19\x01",
            _buildDomainSeparator("Kernel", "0.2.1", sender),
            getStructHash(sig, validUntil, validAfter, validator, executor, enableData)
        )
    );
}

function _buildDomainSeparator(string memory name, string memory version, address verifyingContract)
    view
    returns (bytes32)
{
    bytes32 hashedName = keccak256(bytes(name));
    bytes32 hashedVersion = keccak256(bytes(version));
    bytes32 typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    return keccak256(abi.encode(typeHash, hashedName, hashedVersion, block.chainid, address(verifyingContract)));
}
