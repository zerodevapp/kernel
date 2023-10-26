pragma solidity ^0.8.0;

import "I4337/interfaces/IPaymaster.sol";

contract TestPaymaster is IPaymaster {
    function test_ignore() external {}

    function validatePaymasterUserOp(UserOperation calldata, bytes32, uint256)
        external
        pure
        override
        returns (bytes memory context, uint256 validationData)
    {
        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256) external pure {
        revert("");
    }
}
