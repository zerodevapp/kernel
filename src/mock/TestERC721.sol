// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/tokens/ERC721.sol";

contract TestERC721 is ERC721 {
    constructor() ERC721() {}

    function test_ignore() public {}

    function name() public pure override returns (string memory) {
        return "TestERC721";
    }

    function symbol() public pure override returns (string memory) {
        return "TEST";
    }

    function tokenURI(uint256) public pure override returns (string memory) {
        return "";
    }

    function mint(address _to, uint256 _id) external {
        _mint(_to, _id);
    }

    function safeMint(address _to, uint256 _id) external {
        _safeMint(_to, _id);
    }
}
