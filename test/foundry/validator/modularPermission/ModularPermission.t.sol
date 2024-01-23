import "src/validator/modularPermission/ModularPermissionValidator.sol";
import "forge-std/Test.sol";

contract ModularPermissionTest is Test {
    ModularPermissionValidator validator;

    function setUp() external {
        validator = new ModularPermissionValidator();
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
}
