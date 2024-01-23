pragma solidity ^0.8.0;

import "src/validator/modularPermission/ModularPermissionValidator.sol";
import "src/validator/modularPermission/mock/MockSigner.sol";
import "src/validator/modularPermission/mock/MockPolicy.sol";
import "forge-std/Test.sol";

contract ModularPermissionTest is Test {
    ModularPermissionValidator validator;

    MockSigner mockSigner;
    MockPolicy mockPolicy;

    function setUp() external {
        validator = new ModularPermissionValidator();
        mockPolicy = new MockPolicy();
        mockSigner = new MockSigner();
    }

    function testParseData() external {
        uint48 until = uint48(block.timestamp + 100);
        bytes memory sd = abi.encodePacked("hello world");
        address[] memory p = new address[](2);
        p[0] = address(0xdeadbeef);
        p[1] = address(0xcafecafe);
        bytes[] memory pd = new bytes[](2);
        pd[0] = abi.encodePacked("policy data 1");
        pd[1] = abi.encodePacked("policy data 2");
        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                uint48(1), //`validAfter
                until, // validUntil
                address(0xdead)
            ), // signer
            abi.encode(p, sd, pd)
        );
        (
            uint128 nonce,
            uint48 validAfter,
            uint48 validUntil,
            ISigner signer,
            IPolicy[] memory policies,
            bytes memory signerData,
            bytes[] memory policyData
        ) = validator.parseData(data);
        assertEq(nonce, uint128(0));
        assertEq(validAfter, uint48(1));
        assertEq(validUntil, until);
        assertEq(address(signer), address(0xdead));
        assertEq(address(policies[0]), address(0xdeadbeef));
        assertEq(address(policies[1]), address(0xcafecafe));
        assertEq(signerData, abi.encodePacked("hello world"));
        assertEq(policyData[0], abi.encodePacked("policy data 1"));
        assertEq(policyData[1], abi.encodePacked("policy data 2"));
    }

    function testRegister() external {
        uint48 until = uint48(block.timestamp + 100);
        bytes memory sd = abi.encodePacked("hello signer");
        address[] memory p = new address[](1);
        p[0] = address(mockPolicy);
        bytes[] memory pd = new bytes[](1);
        pd[0] = abi.encodePacked("hello policy");
        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                uint48(1), //`validAfter
                until, // validUntil
                address(mockSigner)
            ), // signer
            abi.encode(p, sd, pd)
        );
        validator.enable(data);
    }

    function testValidateUserOp() external {
        address kernel = makeAddr("Kernel");
        uint48 until = uint48(block.timestamp + 100);
        bytes memory sd = abi.encodePacked("hello signer");
        IPolicy[] memory p = new IPolicy[](1);
        p[0] = mockPolicy;
        bytes[] memory pd = new bytes[](1);
        pd[0] = abi.encodePacked("hello policy");
        bytes32 permissionId = validator.getPermissionId(
            kernel,
            0,
            uint48(1),
            until,
            mockSigner,
            p,
            sd,
            pd
        );

        bytes memory data = abi.encodePacked(
            abi.encodePacked(
                uint128(0), // nonce
                uint48(1), //`validAfter
                until, // validUntil
                address(mockSigner)
            ), // signer
            abi.encode(p, sd, pd)
        );
        vm.startPrank(kernel);
        validator.enable(data);
        vm.stopPrank();

        (
            uint128 nonce,
            uint128 status,
            uint48 validAfter,
            uint48 validUntil,
            ISigner signer,
            IPolicy firstPolicy
        ) = validator.permissions(permissionId, kernel);
        assertEq(nonce, uint128(0));
        assertEq(status, uint128(1));
        assertEq(validAfter, uint48(1));
        assertEq(validUntil, until);
        assertEq(address(signer), address(mockSigner));
        assertEq(address(firstPolicy), address(mockPolicy));

        assertEq(mockSigner.signerData(), sd);
        assertEq(mockPolicy.policyData(), pd[0]);
        UserOperation memory op;
        op.sender = kernel;
        op.signature = abi.encodePacked(permissionId);
        vm.startPrank(kernel);
        validator.validateUserOp(op, keccak256(abi.encodePacked("hello")), 0);
        vm.stopPrank();

        assertEq(mockSigner.count(permissionId), 1);
        assertEq(mockPolicy.count(permissionId), 1);
    }
}
