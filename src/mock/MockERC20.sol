// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/tokens/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20() {}

    function test_ignore() public {}

    function name() public pure override returns (string memory) {
        return "MockERC20";
    }

    function symbol() public pure override returns (string memory) {
        return "MOCK";
    }

    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}
