pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/factory/KernelFactory.sol";
import "src/interfaces/IAddressBook.sol";
import "src/abstract/KernelStorage.sol";
import "src/validator/MultiECDSAValidatorNew.sol";

contract MultiECDSAFactoryPatch is KernelFactory, IAddressBook {
    address[] owners;
    Kernel public kernel;
    MultiECDSAValidatorNew public multiECDSAValidatorNew;

    constructor(
        address _owner,
        IEntryPoint _entryPoint,
        Kernel _kernel,
        MultiECDSAValidatorNew _multiECDSAValidatorNew
    ) KernelFactory(_owner, _entryPoint) {
        kernel = _kernel;
        multiECDSAValidatorNew = _multiECDSAValidatorNew;
    }

    function getOwners() external view override returns (address[] memory) {
        return owners;
    }

    function setOwners(address[] memory _owners) external onlyOwner {
        owners = _owners;
    }

    function createAccount(
        uint256 _index
    ) external payable returns (address proxy) {
        bytes memory data = abi.encodeWithSelector(
            KernelStorage.initialize.selector,
            multiECDSAValidatorNew,
            abi.encodePacked(address(this))
        );
        proxy = this.createAccount(address(kernel), data, _index);
    }

    function getAccountAddress(uint256 _index) public view returns (address) {
        bytes memory _data = abi.encodeWithSelector(
            KernelStorage.initialize.selector,
            multiECDSAValidatorNew,
            abi.encodePacked(address(this))
        );
        return this.getAccountAddress(_data, _index);
    }
}
