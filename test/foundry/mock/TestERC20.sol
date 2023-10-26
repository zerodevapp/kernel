// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/tokens/ERC20.sol";

contract TestERC20 is ERC20 {
    constructor() ERC20() {}

    function test_ignore() public {}

    function name() public pure override returns (string memory) {
        return "TestERC20";
    }

    function symbol() public pure override returns (string memory) {
        return "TST";
    }

    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}
