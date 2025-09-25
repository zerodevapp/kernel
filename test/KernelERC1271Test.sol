pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelHelper} from "src/KernelHelper.sol";
import {SelectorManager} from "src/core/SelectorManager.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {LibString} from "solady/utils/LibString.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockHook} from "./mock/MockHook.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockERC721} from "./mock/MockERC721.sol";
import {MockERC1155} from "./mock/MockERC1155.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {MockKernel} from "./mock/MockKernel.sol";
import {IHook, IValidator} from "src/interfaces/IERC7579Modules.sol";
import {CallType} from "src/types/Types.sol";
import "src/types/Constants.sol";
import "forge-std/console.sol";
import "src/types/Error.sol";
import "src/types/Events.sol";
import "src/types/Structs.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

abstract contract KernelERC1271Test is KernelTestBase {
    function test_erc7739() public {
        assertEq(
            kernel.isValidSignature(0x7739773977397739773977397739773977397739773977397739773977397739, ""),
            bytes4(0x77390001)
        );
    }

    function test_erc1271_root() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);
        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes20(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_fail_invalid() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);
        bytes4 ret =
            kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes20(address(this)), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_root_fail() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, false);
        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes20(0), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_root_personal_sign() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toERC1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, true);
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes20(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_root_personal_sign_fail() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toERC1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, false);
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes20(0), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_validator() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_validator_fail() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, false);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_validator_personal_sign() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toERC1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, true);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes20(address(newValidator)), sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_validator_personal_sign_fail() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toERC1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, false);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes20(address(newValidator)), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_permission() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, true);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(permissionId, sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_permission_fail() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, false);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(permissionId, sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_permission_personal_sign() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toERC1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, true);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(permissionId, sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_permission_personal_sign_fail() external unitTest {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toERC1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, false);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(permissionId, sig));
        assertEq(ret, ERC1271_INVALID);
    }

    // Code heavily inspired by solady's erc1271, erc4337 test file
    bytes32 internal constant _DOMAIN_SEP_B = 0xa1a044077d7677adbbfa892ded5390979b33993e0e2a457e3f974bbcda53821b;

    function _erc1271Signature(
        bytes32 hash,
        bytes memory contentsType,
        bytes memory contentsName,
        function(bytes32, bool) returns(bytes memory) signFn,
        bool isExplicit,
        bool success
    ) internal returns (bytes32 contentsHash, bytes memory sig) {
        contentsHash = keccak256(abi.encode(hash, contentsType));
        bytes32 actualHash;
        if (isExplicit) {
            actualHash = _toERC1271Hash(address(kernel), contentsHash, contentsType, contentsName);
        } else {
            actualHash = _toERC1271Hash(address(kernel), contentsHash, contentsType, _contentsName(contentsType));
        }
        sig = signFn(actualHash, success);
        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName);

        sig =
            abi.encodePacked(sig, _DOMAIN_SEP_B, contentsHash, contentsDescription, uint16(contentsDescription.length));
    }

    function _toERC1271Hash(address account, bytes32 contents, bytes memory contentsType, bytes memory contentsName)
        internal
        view
        returns (bytes32)
    {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(_typedDataSignTypeHash(contentsType, contentsName), contents),
                _accountDomainStructFields(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEP_B, parentStructHash));
    }

    struct _AccountDomainStruct {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        bytes32 salt;
    }

    function _toContentsHash(bytes32 contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _DOMAIN_SEP_B, contents));
    }

    function _accountDomainStructFields(address account) internal view returns (bytes memory) {
        _AccountDomainStruct memory t;
        (, t.name, t.version, t.chainId, t.verifyingContract, t.salt,) = kernel.eip712Domain();

        return abi.encode(keccak256(bytes(t.name)), keccak256(bytes(t.version)), t.chainId, t.verifyingContract, t.salt);
    }

    function _toERC1271HashPersonalSign(bytes32 childHash) internal view returns (bytes32) {
        _AccountDomainStruct memory t;
        (, t.name, t.version, t.chainId, t.verifyingContract, t.salt,) = kernel.eip712Domain();

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(abi.encodePacked(t.name)),
                keccak256(abi.encodePacked(t.version)),
                t.chainId,
                t.verifyingContract
            )
        );
        bytes32 parentStructHash = keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), childHash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, parentStructHash));
    }

    function _typedDataSignTypeHash(bytes memory contentsType, bytes memory contentsName)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
    }

    function _contentsName(bytes memory contentsType) internal pure returns (bytes memory) {
        string memory ct = string(contentsType);
        return bytes(LibString.slice(ct, 0, LibString.indexOf(ct, "(", 0)));
    }
}
