pragma solidity ^0.8.0;

import "account-abstraction/interfaces/IEntryPoint.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "src/Kernel.sol";
import "src/abstract/KernelStorage.sol";

bytes32 constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

struct TempStorage {
    address newTemplate;
    address validator;
    bytes data;
    bytes validatorData;
}

using ECDSA for bytes32;

contract TempKernel is EIP712, IAccount {
    string public constant name = "Kernel";

    string public constant version = "0.0.2";

    IEntryPoint public immutable entryPoint;

    /// @dev Sets up the EIP712 and KernelStorage with the provided entry point
    constructor(IEntryPoint _entryPoint) EIP712(name, version) {
        entryPoint = _entryPoint;
    }

    // Function to initialize the wallet kernel
    function initialize(IKernelValidator _defaultValidator, address _newTemplate, bytes calldata _data) external {
        WalletKernelStorage storage ws = getKernelStorage();
        require(address(ws.defaultValidator) == address(0), "account: already initialized");
        ws.defaultValidator = _defaultValidator;
        // _defaultValidator.enable(_data); removed to avoid accessing external storage
        getStorage().newTemplate = _newTemplate;
        getStorage().data = _data;

        (bool success,) =
            _callCode(address(_defaultValidator), abi.encodeWithSelector(IKernelValidator.enable.selector, _data)); // to NOT preserve msg.sender
        require(success, "account: enable failed with defaultvalidator");
    }

    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zerodev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    function getTempStorage() external view returns (address newTemplate, bytes memory data) {
        TempStorage storage strg = getStorage();
        newTemplate = strg.newTemplate;
        data = strg.data;
    }

    function getStorage() internal view returns (TempStorage storage strg) {
        assembly {
            strg.slot := address()
        }
    }

    /// @notice Validates a user operation based on its mode
    /// @dev This function will validate user operation and be called by EntryPoint
    /// @param userOp The user operation to be validated
    /// @param userOpHash The hash of the user operation
    /// @param missingAccountFunds The funds needed to be reimbursed
    /// @return validationData The data used for validation
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(msg.sender == address(entryPoint), "account: not from entryPoint");
        // mode based signature
        bytes4 mode = bytes4(userOp.signature[0:4]); // mode == 00..00 use validators
        // mode == 0x00000000 use sudo validator
        // mode == 0x00000001 use given validator
        // mode == 0x00000002 enable validator
        UserOperation memory op = userOp;
        IKernelValidator validator;
        bytes4 sig = bytes4(userOp.callData[0:4]);
        if (mode == 0x00000000) {
            // sudo mode (use default validator)
            op = userOp;
            op.signature = userOp.signature[4:];
            validator = getKernelStorage().defaultValidator;
        } else if (mode == 0x00000002) {
            // no plugin mode
            // use given validator
            // userOp.signature[4:10] = validUntil,
            // userOp.signature[10:16] = validAfter,
            // userOp.signature[16:36] = validator address,
            validator = IKernelValidator(address(bytes20(userOp.signature[16:36])));
            bytes calldata enableData;
            bytes calldata remainSig;
            (validationData, enableData, remainSig) = _approveValidator(sig, userOp.signature);
            (bool s,) =
                _callCode(address(validator), abi.encodeWithSelector(IKernelValidator.enable.selector, enableData)); // callcode for NOT preserving msg.sender
            require(s, "account: enable mode enable failed");
            op.signature = remainSig;
        } else {
            return SIG_VALIDATION_FAILED;
        }
        if (missingAccountFunds > 0) {
            // we are going to assume signature is valid at this point
            (bool s,) = msg.sender.call{value: missingAccountFunds}("");
            (s);
        }
        (, bytes memory ret) = _callCode(
            address(validator),
            abi.encodeWithSelector(IKernelValidator.validateUserOp.selector, op, userOpHash, missingAccountFunds)
        );
        validationData = _intersectValidationData(validationData, abi.decode(ret, (uint256)));

        return validationData;
    }

    function _approveValidator(bytes4 sig, bytes calldata signature)
        internal
        returns (uint256 validationData, bytes calldata enableData, bytes calldata validationSig)
    {
        uint256 enableDataLength = uint256(bytes32(signature[56:88]));
        enableData = signature[88:88 + enableDataLength];
        uint256 enableSignatureLength = uint256(bytes32(signature[88 + enableDataLength:120 + enableDataLength]));
        bytes32 enableDigest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256("ValidatorApproved(bytes4 sig,uint256 validatorData,address executor,bytes enableData)"),
                    bytes4(sig),
                    uint256(bytes32(signature[4:36])),
                    address(bytes20(signature[36:56])),
                    keccak256(enableData)
                )
            )
        );
        (, bytes memory ret) = _callCode(
            address(getKernelStorage().defaultValidator),
            (
                abi.encodeWithSelector(
                    IKernelValidator.validateSignature.selector,
                    enableDigest,
                    signature[120 + enableDataLength:120 + enableDataLength + enableSignatureLength]
                )
            )
        );
        validationData = _intersectValidationData(
            abi.decode(ret, (uint256)), uint256(bytes32(signature[4:36])) & (uint256(type(uint96).max) << 160)
        );
        validationSig = signature[120 + enableDataLength + enableSignatureLength:];
        getKernelStorage().execution[sig] = ExecutionDetail({
            executor: address(bytes20(signature[36:56])),
            validator: IKernelValidator(address(bytes20(signature[16:36]))),
            validUntil: uint48(bytes6(signature[4:10])),
            validAfter: uint48(bytes6(signature[10:16]))
        });
        getStorage().validator = address(bytes20(signature[16:36]));
        getStorage().validatorData = enableData;
        return (validationData, signature[88:88 + enableDataLength], validationSig);
    }

    receive() external payable {}

    fallback() external payable {
        TempStorage storage strg = getStorage();
        address _newImplementation = strg.newTemplate;
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, _newImplementation)
        } // update implementation address for used on execution phase

        IKernelValidator defaultValidator = IKernelValidator(getKernelStorage().defaultValidator);
        defaultValidator.enable(strg.data);

        IKernelValidator validator = IKernelValidator(getStorage().validator);
        if (address(validator) != address(0)) {
            validator.enable(getStorage().validatorData);
        }

        (bool success, bytes memory ret) = _newImplementation.delegatecall(msg.data);
        require(success, string(ret));
    }

    // WARTNING: this function is NOT VIEW
    /// @notice Checks if a signature is valid
    /// @dev This function checks if a signature is valid based on the hash of the data signed.
    /// @param hash The hash of the data that was signed
    /// @param signature The signature to be validated
    /// @return The magic value 0x1626ba7e if the signature is valid, otherwise returns 0xffffffff.
    function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
        (, bytes memory ret) = _callCode(
            address(getKernelStorage().defaultValidator),
            abi.encodeWithSelector(IKernelValidator.validateSignature.selector, hash, signature)
        );
        uint256 validationData = abi.decode(ret, (uint256));
        ValidationData memory data = _parseValidationData(validationData);
        if (data.validAfter > block.timestamp) {
            return 0xffffffff;
        }
        if (data.validUntil < block.timestamp) {
            return 0xffffffff;
        }
        if (data.aggregator != address(0)) {
            return 0xffffffff;
        }

        return 0x1626ba7e;
    }

    function _callCode(address _target, bytes memory data) internal returns (bool success, bytes memory ret) {
        assembly {
            let result := callcode(gas(), _target, 0, add(data, 0x20), mload(data), 0, 0)
            // Load free memory location
            let ptr := mload(0x40)
            // We allocate memory for the return data by setting the free memory location to
            // current free memory location + data size + 32 bytes for data size value
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            // Store the size
            mstore(ptr, returndatasize())
            // Store the data
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            // Point the return data to the correct memory location
            ret := ptr
            success := result
        }
        require(success, string(ret));
    }
}
