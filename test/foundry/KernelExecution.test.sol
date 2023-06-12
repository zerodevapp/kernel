// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/EIP1967Proxy.sol";
import "src/factory/KernelFactory.sol";
import "src/factory/ECDSAKernelFactory.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestExecutor.sol";
import "src/test/TestERC721.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";
// test actions/validators
import "src/validator/ERC165SessionKeyValidator.sol";
import "src/executor/TokenActions.sol";

using ERC4337Utils for EntryPoint;

contract KernelExecutionTest is Test {
    Kernel kernel;
    KernelFactory factory;
    ECDSAKernelFactory ecdsaFactory;
    EntryPoint entryPoint;
    ECDSAValidator validator;
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
    }

    function test_revert_when_mode_disabled() external {
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001), address(0), empty)
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

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOp.selector, 0, string.concat("AA23 reverted: ", "kernel: mode disabled")
            )
        );
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_sudo() external {
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_mode_2() external {
        TestValidator testValidator = new TestValidator();
        TestExecutor testExecutor = new TestExecutor();
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));

        bytes32 digest = getTypedDataHash(
            address(kernel), TestExecutor.doNothing.selector, 0, 0, address(testValidator), address(testExecutor), ""
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(0),
            uint48(0),
            address(testValidator),
            address(testExecutor),
            uint256(0),
            uint256(65),
            r,
            s,
            v
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        // vm.expectEmit(true, false, false, false);
        // emit TestValidator.TestValidateUserOp(opHash);
        logGas(op);

        entryPoint.handleOps(ops, beneficiary);
    }

    function test_mode_2_1() external {
        TestValidator testValidator = new TestValidator();
        TestExecutor testExecutor = new TestExecutor();
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));

        bytes32 digest = getTypedDataHash(
            address(kernel), TestExecutor.doNothing.selector, 0, 0, address(testValidator), address(testExecutor), ""
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(0),
            uint48(0),
            address(testValidator),
            address(testExecutor),
            uint256(0),
            uint256(65),
            r,
            s,
            v
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        // vm.expectEmit(true, false, false, false);
        // emit TestValidator.TestValidateUserOp(opHash);
        entryPoint.handleOps(ops, beneficiary);
        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        // registered
        op.signature = abi.encodePacked(bytes4(0x00000001));
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_mode_2_erc165() external {
        ERC165SessionKeyValidator sessionKeyValidator = new ERC165SessionKeyValidator();
        TokenActions action = new TokenActions();
        TestERC721 erc721 = new TestERC721();
        erc721.mint(address(kernel), 0);
        erc721.mint(address(kernel), 1);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(TokenActions.transferERC721Action.selector, address(erc721), 0, address(0xdead))
        );
        address sessionKeyAddr;
        uint256 sessionKeyPriv;
        (sessionKeyAddr, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        bytes memory enableData = abi.encodePacked(
            sessionKeyAddr,
            type(IERC721).interfaceId,
            TokenActions.transferERC721Action.selector,
            uint48(0),
            uint48(0),
            uint32(16)
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                TokenActions.transferERC721Action.selector,
                0,
                0,
                address(sessionKeyValidator),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(sessionKeyValidator),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        op.signature = bytes.concat(op.signature, entryPoint.signUserOpHash(vm, sessionKeyPriv, op));

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);

        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(TokenActions.transferERC721Action.selector, address(erc721), 1, address(0xdead))
        );
        op.signature = abi.encodePacked(bytes4(0x00000001), entryPoint.signUserOpHash(vm, sessionKeyPriv, op));
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);

        assertEq(erc721.ownerOf(0), address(0xdead));
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
