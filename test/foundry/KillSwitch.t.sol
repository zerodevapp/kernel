// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/factory/TempKernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/ECDSAKernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/KillSwitchValidator.sol";
import "src/executor/KillSwitchAction.sol";
import "src/factory/EIP1967Proxy.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract KernelExecutionTest is Test {
    Kernel kernel;
    KernelFactory factory;
    ECDSAKernelFactory ecdsaFactory;
    EntryPoint entryPoint;
    ECDSAValidator validator;

    KillSwitchValidator killSwitch;
    KillSwitchAction action;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);

        validator = new ECDSAValidator();
        ecdsaFactory = new ECDSAKernelFactory(factory, validator, entryPoint);

        kernel = Kernel(payable(address(ecdsaFactory.createAccount(owner, 0))));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
        killSwitch = new KillSwitchValidator();
        action = new KillSwitchAction(killSwitch);
    }

    function test_force_unblock() external {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(Kernel.execute.selector, owner, 0, "", Operation.Call)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);


        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector)
        );
        address guardianKeyAddr;
        uint256 guardianKeyPriv;
        (guardianKeyAddr, guardianKeyPriv) = makeAddrAndKey("guardianKey");
        bytes memory enableData = abi.encodePacked(
            guardianKeyAddr
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                KillSwitchAction.toggleKillSwitch.selector,
                0,
                0,
                address(killSwitch),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(killSwitch),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        uint256 pausedUntil = block.timestamp + 1000;

        bytes32 hash = entryPoint.getUserOpHash(op);
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeyPriv, ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(bytes6(uint48(pausedUntil)),hash))));
            bytes memory sig = abi.encodePacked(r, s, v);

            op.signature = bytes.concat(op.signature, bytes6(uint48(pausedUntil)), sig);
        }

        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
        assertEq(kernel.getDisabledMode(), bytes4(0xffffffff));
        assertEq(address(kernel.getDefaultValidator()), address(killSwitch));
        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, guardianKeyPriv, op));
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary); // should revert because kill switch is active
        assertEq(kernel.getDisabledMode(), bytes4(0));
    }

    function test_mode_2() external {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(Kernel.execute.selector, owner, 0, "", Operation.Call)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);


        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector)
        );
        address guardianKeyAddr;
        uint256 guardianKeyPriv;
        (guardianKeyAddr, guardianKeyPriv) = makeAddrAndKey("guardianKey");
        bytes memory enableData = abi.encodePacked(
            guardianKeyAddr
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                KillSwitchAction.toggleKillSwitch.selector,
                0,
                0,
                address(killSwitch),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(killSwitch),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        uint256 pausedUntil = block.timestamp + 1000;

        bytes32 hash = entryPoint.getUserOpHash(op);
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeyPriv, ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(bytes6(uint48(pausedUntil)),hash))));
            bytes memory sig = abi.encodePacked(r, s, v);

            op.signature = bytes.concat(op.signature, bytes6(uint48(pausedUntil)), sig);
        }

        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(kernel.getDefaultValidator()), address(killSwitch));
        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(Kernel.execute.selector, owner, 0, "", Operation.Call)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, ownerKey, op));
        ops[0] = op;
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary); // should revert because kill switch is active
        vm.warp(pausedUntil + 1);
        entryPoint.handleOps(ops, beneficiary); // should not revert because pausedUntil has been passed
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
            _buildDomainSeparator("Kernel", "0.0.2", sender),
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
