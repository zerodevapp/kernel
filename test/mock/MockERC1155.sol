// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/tokens/ERC1155.sol";

contract MockERC1155 is ERC1155 {
    function test_ignore() public {}

    function uri(uint256) public pure override returns (string memory) {
        return "https://example.com";
    }

    function mint(address to, uint256 id, uint256 amount, bytes memory data) public {
        _mint(to, id, amount, data);
    }

    function batchMint(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) public {
        _batchMint(to, ids, amounts, data);
    }
}
