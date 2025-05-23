pragma solidity ^0.8.0;

contract MockCallee {
    uint256 public value;

    event MockEvent(address indexed caller, address indexed here);

    function setValue(uint256 _value) public {
        value = _value;
    }

    function addValue(uint256 _value) public {
        value += _value;
    }

    function emitEvent(bool shouldFail) public {
        if (shouldFail) {
            revert("Hello");
        }
        emit MockEvent(msg.sender, address(this));
    }
}
