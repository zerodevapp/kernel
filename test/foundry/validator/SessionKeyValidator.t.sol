    // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/KernelFactory.sol";
// test artifacts
import "../mock/TestValidator.sol";
import "../mock/TestExecutor.sol";
import "../mock/TestERC721.sol";
import "../mock/TestERC20.sol";
// test utils
import "forge-std/Test.sol";
import "../utils/ERC4337Utils.sol";
// test actions/validators
import "src/validator/SessionKeyValidator.sol";

import {KernelECDSATest} from "../KernelECDSA.t.sol";

using ERC4337Utils for IEntryPoint;

contract SessionKeyValidatorTest is KernelECDSATest {
    SessionKeyValidator sessionKeyValidator;
    TestERC20 testToken;
    TestERC20 testToken2;
    address sessionKey;
    uint256 sessionKeyPriv;

    function setUp() public override {
        super.setUp();
        (sessionKey, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        testToken = new TestERC20();
        testToken2 = new TestERC20();
        sessionKeyValidator = new SessionKeyValidator();
    }

    // scenarios to test
    // mode - 1, 2
    // paymaster - must, any, none
    // ExecRule
    // - when there is runs => when runs expired
    // - when there is validAfter => when validAfter is future
    // - when there is interval => when interval is zero, when interval is not zero
    function test_scenario(
        bool isBatch,
        bool anyPaymaster,
        uint48 runs,
        uint48 validAfter,
        uint48 interval,
        bool wrongExecutionRule,
        bool wrongPermission,
        bool wrongMerkleRoot,
        bool wrongSig
    ) external {
        bool expectedResult = !(
            wrongPermission ||
            wrongMerkleRoot ||
            wrongSig ||
            wrongExecutionRule
        );
    }
}
