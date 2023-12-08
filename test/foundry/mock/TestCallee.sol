pragma solidity ^0.8.0;

contract TestCallee {
    uint256 public result;

    function test_ignore() external {}

    function addTester(uint256 a, uint256 b) external payable {
        result = a + b + msg.value;
    }

    function transferErc20Tester(address token, address to, uint256 amount) external {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(success, string(data));
    }

    function notThis() external {}
}
