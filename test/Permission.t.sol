import "src/core/PermissionManager.sol";
import "forge-std/Test.sol";

contract MockValidatorLib {
    function encode(bytes1 mode, bytes1 vType, bytes20 validatorIdentifierWithoutType, uint16 nonceKey, uint64 nonce)
        external
        pure
        returns (uint256 res)
    {
        return ValidatorLib.encode(mode, vType, validatorIdentifierWithoutType, nonceKey, nonce);
    }

    function encodeAsNonceKey(bytes1 mode, bytes1 vType, bytes20 validatorIdentifierWithoutType, uint16 nonceKey)
        external
        pure
        returns (uint192 res)
    {
        return ValidatorLib.encodeAsNonceKey(mode, vType, validatorIdentifierWithoutType, nonceKey);
    }

    function decode(uint256 nonce)
        external
        pure
        returns (ValidationMode mode, ValidationType vType, ValidationId identifier)
    {
        return ValidatorLib.decode(nonce);
    }

    function validatorToIdentifier(IValidator validator) external pure returns (ValidationId vId) {
        return ValidatorLib.validatorToIdentifier(validator);
    }

    function getType(ValidationId validator) external pure returns (ValidationType vType) {
        return ValidatorLib.getType(validator);
    }

    function getValidator(ValidationId validator) external pure returns (IValidator v) {
        return ValidatorLib.getValidator(validator);
    }

    function getPermissionValidator(PermissionData data) external pure returns (IValidator vId) {
        return ValidatorLib.getPermissionValidator(data);
    }
}

contract PermissionTest is Test {
    MockValidatorLib validatorLib;

    function setUp() external {
        validatorLib = new MockValidatorLib();
    }

    function testDecode() external {
        uint256 nonce = uint256(bytes32(0));
        (ValidationMode vMode, ValidationType vType, ValidationId vId) = validatorLib.decode(nonce);
        assertTrue(vMode == MODE_DEFAULT, "vMode != MODE_DEFAULT");
        assertTrue(vType == TYPE_SUDO, "vType != TYPE_VALIDATOR");
    }

    function testDecode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, sequencialNonce)));
        (ValidationMode vMode, ValidationType vType, ValidationId vId) = validatorLib.decode(nonce);
        assertTrue(vMode == ValidationMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidationType.wrap(vtype), "vType != type");
        assertTrue(
            vId == ValidationId.wrap(bytes21(abi.encodePacked(vtype, vIdWithoutType))), "vId != vIdWithoutType"
        );
    }

    function testEncode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, uint16 nonceKey, uint64 seqNonce) external {
        uint256 encoded = validatorLib.encode(mode, vtype, vIdWithoutType, nonceKey, seqNonce);
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, nonceKey, seqNonce)));
        assertEq(bytes32(nonce), bytes32(encoded));

        uint192 encodedAsNonceKey = validatorLib.encodeAsNonceKey(mode, vtype, vIdWithoutType, nonceKey);
        assertEq(nonce >> 64, encodedAsNonceKey);
    }

    function testValidatorLib(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint16 nonceKey = uint16(bytes2(sequencialNonce));
        uint64 seqNonce = uint64(bytes8(sequencialNonce << 16));
        uint256 encoded = validatorLib.encode(mode, vtype, vIdWithoutType, nonceKey, seqNonce);

        (ValidationMode vMode, ValidationType vType, ValidationId vId) = validatorLib.decode(encoded);
        assertTrue(vMode == ValidationMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidationType.wrap(vtype), "vType != type");
        assertTrue(
            vId == ValidationId.wrap(bytes21(abi.encodePacked(vtype, vIdWithoutType))), "vId != vIdWithoutType"
        );

        IValidator v = validatorLib.getValidator(vId);
        assertEq(address(v), address(vIdWithoutType), "v != vIdWithoutType");

        ValidationId vid = validatorLib.validatorToIdentifier(v);
        assertTrue(
            vid == ValidationId.wrap(bytes21(abi.encodePacked(TYPE_VALIDATOR, vIdWithoutType))),
            "vid != vIdWithoutType"
        );

        ValidationType vt = validatorLib.getType(vId);
        assertTrue(vt == ValidationType.wrap(vtype), "vt != vtype");
    }
}
