pragma solidity ^0.8.0;

contract MockContractETH {
    function useTransfer(address payable recipient, uint256 v) external {
        recipient.transfer(v);
    }

    function useSend(address payable recipient, uint256 v) external {
        require(recipient.send(v), "send failed");
    }
}
