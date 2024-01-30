// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";

import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {IKernel} from "src/interfaces/IKernel.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {KernelStorage} from "src/abstract/KernelStorage.sol";

import {BaseValidatorBenchmark} from "../BaseValidatorBenchmark.t.sol";

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";

import {ECDSA} from "solady/utils/ECDSA.sol";

/// @dev Benchmark of the ECDSA validator
/// @author KONFeature
contract ECDSABenchmark is BaseValidatorBenchmark {
    // @dev the owner of the kernel wallet we will test
    address private _ecdsaOwner;
    uint256 private _ecdsaOwnerKey;

    /// @dev The current validator we will benchmark
    ECDSAValidator private _ecdsaValidator;

    function setUp() public virtual {
        // Create the ecdsa owner
        (_ecdsaOwner, _ecdsaOwnerKey) = makeAddrAndKey("ecdsaOwner");

        // Deploy the ecdsa validator
        _ecdsaValidator = new ECDSAValidator();
        _validator = _ecdsaValidator;

        // Init test suite
        _init();
        _setupKernel();
    }

    /// @dev Get the current validator anme (used for the json output)
    function _getValidatorName() internal view virtual override returns (string memory) {
        return "ECDSA";
    }

    /// @dev The enabled data are used for mode 2, when the validator isn't enabled and should be enable before
    function _getEnableData() internal view virtual override returns (bytes memory) {
        return abi.encodePacked(_ecdsaOwner);
    }

    /// @dev Fetch the data used to disable a kernel account
    function _getDisableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    /// @dev Get the initialisation data for the current validator
    function _getInitData() internal view virtual override returns (bytes memory) {
        return abi.encodeWithSelector(IKernel.initialize.selector, _validator, abi.encodePacked(_ecdsaOwner));
    }

    /// @dev Generate the signature for the given `_userOperation`
    function _generateUserOpSignature(UserOperation memory _userOperation)
        internal
        view
        virtual
        override
        returns (bytes memory)
    {
        return abi.encodePacked(_userOperation.signature);
    }

    /// @dev Generate the signature for the given `_hash`
    function _generateHashSignature(bytes32 _hash) internal view virtual override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_ecdsaOwnerKey, ECDSA.toEthSignedMessageHash(_hash));
        return abi.encodePacked(r, s, v);
    }
}
