pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
import "openzeppelin-contracts/contracts/token/ERC1155/IERC1155.sol";

contract TokenActions {
    function transfer20Action(address _token, uint256 _amount, address _to) external {
        IERC20(_token).transfer(_to, _amount);
    }

    function transferERC721Action(address _token, uint256 _id, address _to) external {
        IERC721(_token).transferFrom(address(this), _to, _id);
    }

    function transferERC1155Action(address _token, uint256 _id, address _to, uint256 amount, bytes calldata data) external {
        IERC1155(_token).safeTransferFrom(address(this), _to, _id, amount, data);
    }
}
