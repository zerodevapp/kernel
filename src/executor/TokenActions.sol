pragma solidity ^0.8.0;

import "solady/tokens/ERC20.sol";
import "solady/tokens/ERC721.sol";
import "solady/tokens/ERC1155.sol";

contract TokenActions {
    function transferERC20Action(address _token, uint256 _amount, address _to) external {
        ERC20(_token).transfer(_to, _amount);
    }

    function transferERC721Action(address _token, uint256 _id, address _to) external {
        ERC721(_token).transferFrom(address(this), _to, _id);
    }

    function transferERC1155Action(address _token, uint256 _id, address _to, uint256 amount, bytes calldata data)
        external
    {
        ERC1155(_token).safeTransferFrom(address(this), _to, _id, amount, data);
    }
}
