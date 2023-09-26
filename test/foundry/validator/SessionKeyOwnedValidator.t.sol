// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/AdminLessERC1967Factory.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/KernelFactory.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestExecutor.sol";
import "src/test/TestERC721.sol";
import "src/test/TestERC20.sol";
// test utils
import "forge-std/Test.sol";
import "test/foundry/utils/ERC4337Utils.sol";
// test actions/validators
import "src/validator/SessionKeyOwnedValidator.sol";

using ERC4337Utils for EntryPoint;

contract SessionKeyOwnedValidatorTest is KernelTestBase {
    SessionKeyOwnedValidator sessionKeyValidator;
    TestERC20 testToken;
    address sessionKey;
    uint256 sessionKeyPriv;

    uint48 validAfter = uint48(0);
    uint48 validUntil = type(uint48).max;

    function setUp() public {
        _initialize();
        defaultValidator = new ECDSAValidator();
        sessionKeyValidator = new SessionKeyOwnedValidator();
        _setAddress();
        (sessionKey, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        testToken = new TestERC20();
    }

    function test_mode_2_no_paymaster() external {
        testToken.mint(address(kernel), 100e18);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                Kernel.execute.selector,
                address(testToken),
                0,
                abi.encodeWithSelector(ERC20.transfer.selector, beneficiary, 100),
                Operation.Call
            )
        );

        bytes memory enableData = abi.encodePacked(sessionKey, validAfter, validUntil);

        bytes32 digest = getTypedDataHash(
            address(kernel),
            Kernel.execute.selector,
            validAfter,
            validUntil,
            address(sessionKeyValidator),
            address(0),
            enableData
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            validAfter,
            validUntil,
            address(sessionKeyValidator),
            address(0),
            uint256(enableData.length),
            enableData,
            uint256(65),
            r,
            s,
            v,
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);

        entryPoint.handleOps(ops, beneficiary);
    }
}
