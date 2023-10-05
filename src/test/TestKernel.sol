pragma solidity ^0.8.0;

import "../Kernel.sol";

contract TestKernel is Kernel {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {}

    function test() public {}

    function sudoInitialize(IKernelValidator _defaultValidator, bytes calldata _data) external payable {
        WalletKernelStorage storage ws = getKernelStorage();
        ws.defaultValidator = _defaultValidator;
        emit DefaultValidatorChanged(address(0), address(_defaultValidator));
        _defaultValidator.enable(_data);
    }
}
