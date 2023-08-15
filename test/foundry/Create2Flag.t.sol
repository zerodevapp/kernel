pragma solidity ^0.8.0;

import "src/utils/Create2Flag.sol";
import "forge-std/Test.sol";

contract Create2FlagTest is Test {
    function test_deploy(bytes32 key) external {
        address addr = Create2Flag.getFlagAddress(key);
        Create2Flag.on(key);
        assertEq(addr.code.length > 0, true);
        assertEq(keccak256(addr.code), keccak256(hex"060000000000"));
        assertEq(Create2Flag.isOff(key), false);
    }
}
