pragma solidity ^0.8.0;

contract TestCallee {
    uint256 public result;
    address public caller;
    uint256 public sent;
    bytes public message;

    receive() external payable {}

    fallback() external payable {
        message = msg.data;
        sent = msg.value;
        caller = msg.sender;
    }

    function test_ignore() external {}

    function addTester(uint256 a, uint256 b) external payable {
        result = a + b + msg.value;
    }

    function transferErc20Tester(address token, address to, uint256 amount) external {
        (bool success, bytes memory data) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(success, string(data));
    }

    function returnLong() external payable returns (string memory) {
        return
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent nec nunc sed nisi sollicitudin suscipit at at nulla. Aenean porttitor tellus felis, dapibus lacinia elit ullamcorper id. Ut dapibus efficitur neque posuere varius. Aenean in sem ac dolor accumsan egestas ut sit amet arcu. Vestibulum nunc urna, imperdiet ut enim eu, venenatis placerat mi. Aliquam a nibh a augue sollicitudin rutrum. Donec eleifend semper elit eu facilisis.";
    }

    function returnLongBytes() external payable returns (bytes memory) {
        return
        hex"0000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    }

    function notThis() external {}
}
