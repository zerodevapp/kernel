// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {ECDSAValidator} from "../mock/ECDSAValidator.sol";
import {ERC1271_MAGICVALUE, MODULE_TYPE_VALIDATOR, VALIDATION_TYPE_VALIDATOR} from "src/types/Constants.sol";
import {ValidationType} from "src/types/Types.sol";

/// @notice Kernel7702 allows raw (non-nested) ERC-1271 so the account matches the signing behavior
///         of the EOA it delegates from. That exemption is sound only for the fallback signer,
///         whose key *is* the account address. Installed validators are not account-bound, so a raw
///         signature they accept would be valid on every account sharing the module.
contract Erc1271AccountBindingTest is Test {
    IEntryPoint ep;
    Kernel7702 template;
    ECDSAValidator validator;

    Kernel alice;
    uint256 aliceKey;
    Kernel bob;

    address sessionSigner;
    uint256 sessionKey;

    function setUp() public {
        ep = EntryPointLib.deploy();
        template = new Kernel7702(ep);
        validator = new ECDSAValidator();
        (sessionSigner, sessionKey) = makeAddrAndKey("SharedSessionSigner");

        (alice, aliceKey) = _delegate("Alice");
        (bob,) = _delegate("Bob");
    }

    function test_RawValidatorSignatureIsRejected() external {
        bytes32 appHash = keccak256("app payload that does not name the account");
        bytes memory sig = _validatorSig(_sign(sessionKey, appHash));

        assertTrue(
            alice.isValidSignature(appHash, sig) != ERC1271_MAGICVALUE,
            "raw mode must not dispatch to installed validators"
        );
        assertTrue(bob.isValidSignature(appHash, sig) != ERC1271_MAGICVALUE, "and must not replay to another account");
    }

    function test_NestedValidatorSignatureDoesNotReplayAcrossAccounts() external {
        bytes32 appHash = keccak256("app payload that does not name the account");
        bytes memory sig = _validatorSig(_sign(sessionKey, _personalSignDigest(address(alice), appHash)));

        assertEq(alice.isValidSignature(appHash, sig), ERC1271_MAGICVALUE, "nested path must still validate");
        assertTrue(
            bob.isValidSignature(appHash, sig) != ERC1271_MAGICVALUE, "nested signature is bound to alice's domain"
        );
    }

    /// @dev The reason raw mode exists: the 7702 fallback signer keeps working without wrapping.
    ///      Only asserted against alice — presenting a bare ECDSA signature to another account
    ///      reverts with `InvalidValidationType`, since its first byte is then read as a validation
    ///      type by the nested path. That behavior predates this test; see test/btt/Kernel7702.t.sol.
    function test_RawFallbackSignatureStillWorks() external {
        bytes32 appHash = keccak256("app payload that does not name the account");

        assertEq(
            alice.isValidSignature(appHash, _sign(aliceKey, appHash)),
            ERC1271_MAGICVALUE,
            "raw EOA signature must stay valid"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _delegate(string memory name) internal returns (Kernel kernel, uint256 key) {
        address eoa;
        (eoa, key) = makeAddrAndKey(name);
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));
        vm.prank(address(ep));
        kernel.installModule(
            MODULE_TYPE_VALIDATOR, address(validator), abi.encode(abi.encodePacked(sessionSigner), hex"")
        );
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _validatorSig(bytes memory sig) internal view returns (bytes memory) {
        return abi.encodePacked(ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR), bytes20(address(validator)), sig);
    }

    /// @dev The ERC-7739 `PersonalSign` digest for `account`, which is what the nested flow checks.
    function _personalSignDigest(address account, bytes32 childHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            Kernel(payable(account)).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        bytes32 structHash = keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), childHash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
