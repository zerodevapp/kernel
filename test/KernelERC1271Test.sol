pragma solidity ^0.8.0;

import {LibString} from "solady/utils/LibString.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {Install} from "src/types/Structs.sol";
import {Kernel} from "src/Kernel.sol";
import {InvalidValidationType, InvalidValidator, InvalidPermissionId} from "src/types/Error.sol";
import {MockValidator} from "./mock/MockValidator.sol";

abstract contract KernelERC1271Test is KernelTestBase {
    modifier erc1271Test() {
        vm.txGasPrice(1);
        _;
    }

    function test_erc7739() public erc1271Test {
        assertEq(
            kernel.isValidSignature(0x7739773977397739773977397739773977397739773977397739773977397739, ""),
            bytes4(0x77390001)
        );
    }

    function test_erc1271_root() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);
        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_fail_invalid() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, true);
        vm.expectRevert();
        kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(this)), sig)
        );
    }

    function test_erc1271_root_fail() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _rootSignHash, false, false);
        bytes4 ret = kernel.isValidSignature(_toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_root_personal_sign() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, true);
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_root_personal_sign_fail() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _rootSignHash(personalHash, false);
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0), sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_validator() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, true);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_validator_fail() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, false);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash),
            abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_validator_personal_sign() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, true);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(
            messageHash, abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_validator_personal_sign_fail() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _validatorSignHash(personalHash, false);
        kernel.installModule(1, address(newValidator), abi.encode(hex"", hex""));
        bytes4 ret = kernel.isValidSignature(
            messageHash, abi.encodePacked(bytes1(0), bytes1(0x01), bytes20(address(newValidator)), sig)
        );
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_permission() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, true);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_permission_fail() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        (bytes32 contentsHash, bytes memory sig) =
            _erc1271Signature(messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, false);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(
            _toContentsHash(contentsHash), abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig)
        );
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_permission_personal_sign() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, true);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_erc1271_permission_personal_sign_fail() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, false);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0x02), permissionId, sig));
        assertEq(ret, ERC1271_INVALID);
    }

    function test_erc1271_invalid_validation_type() external unitTest erc1271Test {
        bytes32 messageHash = keccak256("Hello world");
        bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
        bytes memory sig = _permissionSignHash(personalHash, false);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(messageHash, abi.encodePacked(bytes1(0), bytes1(0xee), permissionId, sig));
    }

    function test_erc1271_enable_validator() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: true, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_validator_fail_validator_not_exist() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: true, personalSign: false, vIdExist: false
            })
        );
    }

    function test_erc1271_enable_validator_fail() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: false, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_validator_personal_sign() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: true, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_validator_personal_sign_fail() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: false, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_validator() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: true, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_validator_fail() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: false, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_validator_personal_sign() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: true, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_validator_personal_sign_fail() external unitTest erc1271Test {
        _testSigEnableValidator(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: false, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_permission() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: true, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_permission_fail_validator_not_exist() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: true, personalSign: false, vIdExist: false
            })
        );
    }

    function test_erc1271_enable_permission_fail() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: false, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_permission_personal_sign() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: true, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_permission_personal_sign_fail() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: false, enableSuccess: true, signatureSuccess: false, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_permission() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: true, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_permission_fail() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: false, personalSign: false, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_permission_personal_sign() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: true, personalSign: true, vIdExist: true
            })
        );
    }

    function test_erc1271_enable_replayable_permission_personal_sign_fail() external unitTest erc1271Test {
        _testSigEnablePermission(
            EnableTestParam({
                replayable: true, enableSuccess: true, signatureSuccess: false, personalSign: true, vIdExist: true
            })
        );
    }

    struct EnableTestParam {
        bool replayable;
        bool enableSuccess;
        bool signatureSuccess;
        bool personalSign;
        bool vIdExist;
    }

    function _testSigEnableValidator(EnableTestParam memory args) internal {
        bytes32 messageHash = keccak256("Hello world");
        bytes memory sig;
        if (args.personalSign) {
            bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
            sig = _validatorSignHash(personalHash, args.signatureSuccess);
        } else {
            bytes32 contentsHash;
            (contentsHash, sig) = _erc1271Signature(
                messageHash, "C(bytes32 stuff)", "", _validatorSignHash, false, args.signatureSuccess
            );
            messageHash = _toContentsHash(contentsHash);
        }
        Install[] memory packages = new Install[](1);
        if (args.vIdExist) {
            packages[0] =
                Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        } else {
            MockValidator mockValidator = new MockValidator();
            mockValidator.sudoSetSuccess(true);
            packages[0] =
                Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        }
        uint8 uMode = 0;
        // enable mode flag
        uMode += 2 ** 3;
        if (args.replayable) {
            uMode += 2 ** 2;
        }
        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x01),
            newValidator,
            abi.encode(
                uint256(0), packages, enableSig(0, args.enableSuccess, args.replayable, packages, _rootSignHash), sig
            )
        );

        if (args.vIdExist) {
            bytes4 res = kernel.isValidSignature(messageHash, sigWithEnable);
            assertEq(res, args.signatureSuccess ? ERC1271_MAGICVALUE : ERC1271_INVALID);

            if (!isMock) {
                vm.chainId(1000);
                res = kernel.isValidSignature(messageHash, sigWithEnable);
                assertEq(res, args.signatureSuccess && args.replayable ? ERC1271_MAGICVALUE : ERC1271_INVALID);
            }
        } else {
            vm.expectRevert(InvalidValidator.selector);
            kernel.isValidSignature(messageHash, sigWithEnable);
        }
    }

    function _testSigEnablePermission(EnableTestParam memory args) internal {
        bytes32 messageHash = keccak256("Hello world");
        bytes memory sig;
        if (args.personalSign) {
            bytes32 personalHash = _toErc1271HashPersonalSign(messageHash);
            sig = _permissionSignHash(personalHash, args.signatureSuccess);
        } else {
            bytes32 contentsHash;
            (contentsHash, sig) = _erc1271Signature(
                messageHash, "C(bytes32 stuff)", "", _permissionSignHash, false, args.signatureSuccess
            );
            messageHash = _toContentsHash(contentsHash);
        }
        Install[] memory packages = new Install[](2);
        if (args.vIdExist) {
            packages[0] = Install({
                moduleType: 5, module: address(policy), moduleData: hex"", internalData: abi.encodePacked(permissionId)
            });
            packages[1] = Install({
                moduleType: 6, module: address(signer), moduleData: hex"", internalData: abi.encodePacked(permissionId)
            });
        } else {
            packages[0] = Install({
                moduleType: 5, module: address(policy), moduleData: hex"", internalData: abi.encodePacked(hex"cafecafe")
            });
            packages[1] = Install({
                moduleType: 6, module: address(signer), moduleData: hex"", internalData: abi.encodePacked(hex"cafecafe")
            });
        }
        uint8 uMode = 0;
        // enable mode flag
        uMode += 2 ** 3;
        if (args.replayable) {
            uMode += 2 ** 2;
        }
        bytes memory sigWithEnable = abi.encodePacked(
            uMode,
            bytes1(0x02),
            permissionId,
            abi.encode(
                uint256(0), packages, enableSig(0, args.enableSuccess, args.replayable, packages, _rootSignHash), sig
            )
        );
        if (args.vIdExist) {
            bytes4 res = kernel.isValidSignature(messageHash, sigWithEnable);
            assertEq(res, args.signatureSuccess ? ERC1271_MAGICVALUE : ERC1271_INVALID);

            if (!isMock) {
                vm.chainId(1000);
                res = kernel.isValidSignature(messageHash, sigWithEnable);
                assertEq(res, args.signatureSuccess && args.replayable ? ERC1271_MAGICVALUE : ERC1271_INVALID);
            }
        } else {
            vm.expectRevert(InvalidPermissionId.selector);
            kernel.isValidSignature(messageHash, sigWithEnable);
        }
    }

    // Code heavily inspired by solady's erc1271, erc4337 test file
    bytes32 internal constant _DOMAIN_SEP_B = 0xa1a044077d7677adbbfa892ded5390979b33993e0e2a457e3f974bbcda53821b;

    function _erc1271Signature(
        bytes32 hash,
        bytes memory contentsType,
        bytes memory contentsName,
        function(bytes32, bool) returns (bytes memory) signFn,
        bool isExplicit,
        bool success
    ) internal returns (bytes32 contentsHash, bytes memory sig) {
        contentsHash = keccak256(abi.encode(hash, contentsType));
        bytes32 actualHash;
        if (isExplicit) {
            actualHash = _toErc1271Hash(address(kernel), contentsHash, contentsType, contentsName);
        } else {
            actualHash = _toErc1271Hash(address(kernel), contentsHash, contentsType, _contentsName(contentsType));
        }
        sig = signFn(actualHash, success);
        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName);

        sig =
            abi.encodePacked(sig, _DOMAIN_SEP_B, contentsHash, contentsDescription, uint16(contentsDescription.length));
    }

    function _toErc1271Hash(address account, bytes32 contents, bytes memory contentsType, bytes memory contentsName)
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

    struct AccountDomainStruct {
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
        AccountDomainStruct memory t;
        (, t.name, t.version, t.chainId, t.verifyingContract, t.salt,) = Kernel(payable(account)).eip712Domain();

        return abi.encode(keccak256(bytes(t.name)), keccak256(bytes(t.version)), t.chainId, t.verifyingContract, t.salt);
    }

    function _toErc1271HashPersonalSign(bytes32 childHash) internal view returns (bytes32) {
        AccountDomainStruct memory t;
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
