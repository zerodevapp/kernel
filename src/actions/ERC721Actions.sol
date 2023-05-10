// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";

contract ERC721Actions {
    function transferERC721Action(address _token, uint256 _id, address _to) external {
        IERC721(_token).transferFrom(address(this), _to, _id);
    }
}