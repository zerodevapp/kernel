// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/EIP1967Proxy.sol";
// test artifacts
import "src/test/TestValidator.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract KernelExecutionTest is Test {
    Kernel implementation;
    Kernel kernel;
    EntryPoint entryPoint;
    ECDSAValidator validator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        entryPoint = new EntryPoint();
        implementation = new Kernel(entryPoint);
        validator = new ECDSAValidator();

        kernel = Kernel(
            payable(
                address(
                    new EIP1967Proxy(
                    address(implementation),
                    abi.encodeWithSelector(
                    implementation.initialize.selector,
                    validator,
                    abi.encodePacked(owner)
                    )
                    )
                )
            )
        );
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_revert_when_mode_disabled() external {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001))
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        // try to run with mode 0x00000001
        op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001))
        );
        op.signature = abi.encodePacked(bytes4(0x00000001), entryPoint.signUserOpHash(vm, ownerKey, op));
        ops[0] = op;

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, string.concat("AA23 reverted: ", "kernel: mode disabled")));
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_mode_1() external {
        TestValidator testValidator = new TestValidator();
         UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(Kernel.execute.selector, address(0xdeadbeef), 1, "")
        );

        bytes32 digest = getTypedDataHash(address(kernel), Kernel.execute.selector, 0,0, address(testValidator), address(0), "");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        op.signature = abi.encodePacked(bytes4(0x00000001), uint48(0), uint48(0), address(testValidator), address(0), uint256(0), uint256(65), r,s,v);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        // vm.expectEmit(true, false, false, false);
        // emit TestValidator.TestValidateUserOp(opHash);
        entryPoint.handleOps(ops, beneficiary);
    }
}


// computes the hash of a permit
function getStructHash(bytes4 sig, uint48 validUntil, uint48 validAfter, address validator, address executor, bytes memory enableData)
    pure
    returns (bytes32)
{
    return
        keccak256(
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
function getTypedDataHash(address sender, bytes4 sig, uint48 validUntil, uint48 validAfter, address validator, address executor, bytes memory enableData)
    view
    returns (bytes32)
{
    return
        keccak256(
            abi.encodePacked(
                "\x19\x01",
                _buildDomainSeparator("Kernel", "0.0.2", sender),
                getStructHash(sig, validUntil, validAfter, validator, executor, enableData)
            )
        );
}

function _buildDomainSeparator(
    string memory name,
    string memory version,
    address verifyingContract
) view returns (bytes32) {
    bytes32 hashedName = keccak256(bytes(name));
    bytes32 hashedVersion = keccak256(bytes(version));
    bytes32 typeHash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    return keccak256(abi.encode(typeHash, hashedName, hashedVersion, block.chainid, address(verifyingContract)));
}
