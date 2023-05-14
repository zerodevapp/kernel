// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/interfaces/IEntryPoint.sol";
import "src/validator/IValidator.sol";

struct ExectionDetail {
    address executor;
    IKernelValidator validator;
}

struct WalletKernelStorage {
    bytes32 __deprecated;
    IKernelValidator defaultValidator;
    bytes4 disabledMode;
    mapping(bytes4 => ExectionDetail) execution;
}

contract KernelStorage {
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    IEntryPoint public immutable entryPoint;

    event Upgraded(address indexed newImplementation);

    // modifier for checking if the sender is the entrypoint or
    // the account itself
    modifier onlyFromEntryPointOrOwnerOrSelf() {
        require(
            msg.sender == address(entryPoint) || msg.sender == address(this),
            "account: not from entrypoint or owner or self"
        );
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        getKernelStorage().defaultValidator = IKernelValidator(address(1));
    }

    /// @notice initialize wallet kernel
    /// @dev this function should be called only once, implementation initialize is blocked by owner = address(1)
    /// @param _defaultValidator owner address
    function initialize(IKernelValidator _defaultValidator, bytes calldata _data) external {
        WalletKernelStorage storage ws = getKernelStorage();
        require(address(ws.defaultValidator) == address(0), "account: already initialized");
        ws.defaultValidator = _defaultValidator;
        _defaultValidator.enable(_data);
    }

    /// @notice get wallet kernel storage
    /// @dev used to get wallet kernel storage
    /// @return ws wallet kernel storage, consists of owner and nonces
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zerodev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    function upgradeTo(address _newImplementation) external onlyFromEntryPointOrOwnerOrSelf {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    // nonce from entrypoint
    function getNonce() public view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), 0);
    }

    function getNonce(uint192 key) public view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), key);
    }

    // query storage
    function getDefaultValidator() public view returns (IKernelValidator) {
        return getKernelStorage().defaultValidator;
    }

    function getDisabledMode() public view returns (bytes4) {
        return getKernelStorage().disabledMode;
    }

    function getExecution(bytes4 _selector) public view returns (ExectionDetail memory) {
        return getKernelStorage().execution[_selector];
    }

    // change storage
    function setExecution(bytes4 _selector, address _executor, IKernelValidator _validator)
        external
        onlyFromEntryPointOrOwnerOrSelf
    {
        getKernelStorage().execution[_selector] = ExectionDetail({executor: _executor, validator: _validator});
    }

    function setDefaultValidator(IKernelValidator _defaultValidator) external onlyFromEntryPointOrOwnerOrSelf {
        getKernelStorage().defaultValidator = _defaultValidator;
    }

    function disableMode(bytes4 _disableFlag) external onlyFromEntryPointOrOwnerOrSelf {
        getKernelStorage().disabledMode = _disableFlag;
    }
}
