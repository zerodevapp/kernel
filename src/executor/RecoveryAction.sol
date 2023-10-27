pragma solidity ^0.8.0;

import "src/interfaces/IKernelValidator.sol";

contract RecoveryAction {
    function doRecovery(address _validator, bytes calldata _data) external {
        IKernelValidator(_validator).enable(_data);
    }
}
