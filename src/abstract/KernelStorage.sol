// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Importing necessary interfaces
import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {IKernel} from "../interfaces/IKernel.sol";
import {KERNEL_STORAGE_SLOT, KERNEL_STORAGE_SLOT_1, IMPLEMENTATION_SLOT} from "../common/Constants.sol";
import {ExecutionDetail, WalletKernelStorage} from "../common/Structs.sol";
import {ValidUntil, ValidAfter} from "../common/Types.sol";

/// @title Kernel Storage Contract
/// @author taek<leekt216@gmail.com>
/// @notice This contract serves as the storage module for the Kernel contract.
/// @dev This contract should only be used by the main Kernel contract.
abstract contract KernelStorage is IKernel {
    IEntryPoint public immutable entryPoint; // The entry point of the contract

    // Modifier to check if the function is called by the entry point, the contract itself or the owner
    modifier onlyFromEntryPointOrSelf() {
        if (msg.sender != address(entryPoint) && msg.sender != address(this)) {
            revert NotAuthorizedCaller();
        }
        _;
    }

    /// @param _entryPoint The address of the EntryPoint contract
    /// @dev Sets up the EntryPoint contract address
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        getKernelStorage().defaultValidator = IKernelValidator(address(1));
    }

    // Function to initialize the wallet kernel
    function initialize(IKernelValidator _defaultValidator, bytes calldata _data) external payable override {
        _setInitialData(_defaultValidator, _data);
    }

    // Function to get the wallet kernel storage
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        assembly {
            ws.slot := KERNEL_STORAGE_SLOT
        }
    }

    // Function to upgrade the contract to a new implementation
    function upgradeTo(address _newImplementation) external payable override onlyFromEntryPointOrSelf {
        assembly {
            sstore(IMPLEMENTATION_SLOT, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    // Functions to get the nonce from the entry point
    function getNonce() external view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), 0);
    }

    function getNonce(uint192 key) external view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), key);
    }

    // query storage
    function getDefaultValidator() external view override returns (IKernelValidator validator) {
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
    }

    function getDisabledMode() external view override returns (bytes4 disabled) {
        assembly {
            disabled := shl(224, sload(KERNEL_STORAGE_SLOT_1))
        }
    }

    function getLastDisabledTime() external view override returns (uint48) {
        return getKernelStorage().lastDisabledTime;
    }

    function getExecution(bytes4 _selector) external view override returns (ExecutionDetail memory) {
        return getKernelStorage().execution[_selector];
    }

    function setExecution(
        bytes4 _selector,
        address _executor,
        IKernelValidator _validator,
        ValidUntil _validUntil,
        ValidAfter _validAfter,
        bytes calldata _enableData
    ) external payable override onlyFromEntryPointOrSelf {
        getKernelStorage().execution[_selector] = ExecutionDetail({
            executor: _executor,
            validator: _validator,
            validUntil: _validUntil,
            validAfter: _validAfter
        });
        _validator.enable(_enableData);
        emit ExecutionChanged(_selector, _executor, address(_validator));
    }

    function setDefaultValidator(IKernelValidator _defaultValidator, bytes calldata _data)
        external
        payable
        virtual
        onlyFromEntryPointOrSelf
    {
        IKernelValidator oldValidator = getKernelStorage().defaultValidator;
        getKernelStorage().defaultValidator = _defaultValidator;
        emit DefaultValidatorChanged(address(oldValidator), address(_defaultValidator));
        _defaultValidator.enable(_data);
    }

    function disableMode(bytes4 _disableFlag) external payable override onlyFromEntryPointOrSelf {
        getKernelStorage().disabledMode = _disableFlag;
        getKernelStorage().lastDisabledTime = uint48(block.timestamp);
    }

    function _setInitialData(IKernelValidator _defaultValidator, bytes calldata _data) internal virtual {
        address validator;
        assembly {
            validator := shr(80, sload(KERNEL_STORAGE_SLOT_1))
        }
        if (address(validator) != address(0)) {
            revert AlreadyInitialized();
        }
        getKernelStorage().defaultValidator = _defaultValidator;
        _defaultValidator.enable(_data);
    }
}
