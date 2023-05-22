// SPDX-License-Identifier: MIT
import "./KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";

contract ECDSAKernelFactory {
    KernelFactory immutable public singletonFactory;
    ECDSAValidator immutable public validator;

    constructor(KernelFactory _singletonFactory, ECDSAValidator _validator) {
        singletonFactory = _singletonFactory;
        validator = _validator;
    }

    function createAccount(address _owner, uint256 _index) external returns (EIP1967Proxy proxy) {
        bytes memory data = abi.encodePacked(_owner);
        proxy = singletonFactory.createAccount(validator, data, _index);
    }

    function getAccountAddress(address _owner, uint256 _index) public view returns (address) {
        bytes memory data = abi.encodePacked(_owner);
        return singletonFactory.getAccountAddress(validator, data, _index);
    }
}
