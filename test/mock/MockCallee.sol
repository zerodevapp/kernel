pragma solidity ^0.8.0;

contract MockCallee {
    uint256 public bar;
    string public data;

    event Lorem();

    error Haha();

    function foo() external {
        bar++;
        emit Lorem();
    }

    function lorem() external {
        data = "lorem ipsum";
    }

    function forceRevert() external pure {
        revert Haha();
    }

    function ret(bytes memory dat) external pure returns (bytes memory) {
        return dat;
    }
}
