pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator} from "./interfaces/IERC7579Modules.sol";
import "./types/Types.sol";
import {ModuleManager, Install} from "./core/ModuleManager.sol";
import {ExecutionManager} from "./core/ExecutionManager.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {Lib4337} from "./Lib4337.sol";
import "./types/Error.sol";
import "./types/Events.sol";

contract Kernel is ModuleManager, ExecutionManager, EIP712 {
    IEntryPoint immutable entryPoint;

    error Unauthorized();

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), Unauthorized());
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "0.4.0";
    }

    /// authentication
    struct EnableModeSignature {
        Install[] packages;
        bytes enableSignature;
        bytes userOpSignature;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        onlyEntryPoint
        returns (uint256 validationData)
    {
        (ValidationId verifier, bytes32 opHash, bytes calldata userOpSignature) = _processUserOp(userOp, userOpHash);
        return _verifySignature(verifier, opHash, userOpSignature);
    }

    function _processUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        returns (ValidationId verifier, bytes32 opHash, bytes calldata signature)
    {
        /*
         userOp.nonce = vMode | vType | vId
        */
        (ValidationMode vMode, ValidationType vType, ValidationId vId) = _parseNonce(userOp.nonce);
        _checkValidation(vMode, vType, vId);
        signature = userOp.signature;
        if (isEnable(vMode)) {
            bool enableReplayable = isEnableReplayable(vMode);
            EnableModeSignature calldata sig;
            assembly {
                sig := signature.offset
            }
            signature = sig.userOpSignature;
            _verifyInstallSignature(enableReplayable, sig.packages, sig.enableSignature);
            _install(sig.packages);
        }
        opHash = isReplayable(vMode) ? Lib4337.chainAgnosticUserOpHash(msg.sender, userOp) : userOpHash;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {}

    /// execution
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external payable onlyEntryPoint {
        (bool success, bytes memory ret) = address(this).delegatecall(userOp.callData[4:]);
    }

    function execute(bytes32 mode, bytes calldata executionData) external payable {
        _execute(mode, executionData);
    }

    function executeFromExecutor(bytes32 mode, bytes calldata executionData) external payable {
        _execute(mode, executionData);
    }

    /// management
    struct InstallModuleDataFormat {
        bytes installData;
        bytes internalData;
    }

    function installModule(uint256 moduleType, address module, bytes calldata initData) external payable {
        InstallModuleDataFormat calldata imdf;
        assembly {
            imdf := initData.offset
        }

        _installModule(moduleType, module, imdf.installData, imdf.internalData);
    }

    // NOTE : this ONLY allows root signature
    function installModule(bool replayable, Install[] calldata packages, bytes calldata signature) external {
        require(_verifyInstallSignature(replayable, packages, signature), InstallSignatureVerificationFailed());
        _install(packages);
    }

    function _verifyInstallSignature(bool replayable, Install[] calldata packages, bytes calldata signature)
        internal
        view
        returns (bool success)
    {
        ValidationId vId = _validationStorage().rootValidator;
        function(bytes32) internal view returns(bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        bytes32 digest = hashTypedData(
            keccak256(
                abi.encode(
                    keccak256(
                        "InstallPackages(Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    _installHash(packages)
                )
            )
        );
        _verifySignature(vId, digest, signature);
    }
}
