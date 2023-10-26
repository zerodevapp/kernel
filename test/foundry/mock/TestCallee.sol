pragma solidity ^0.8.0;

contract TestCallee {
    uint256 public result;

    function test_ignore() external {}

    function addTester(uint256 a, uint256 b) external payable {
        result = a + b + msg.value;
    }

    function notThis() external {}
}
