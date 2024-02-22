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

    function decode(uint256 nonce)
        external
        pure
        returns (ValidatorMode mode, ValidatorType vType, ValidatorIdentifier identifier)
    {
        return ValidatorLib.decode(nonce);
    }

    function validatorToIdentifier(IValidator validator) external pure returns (ValidatorIdentifier vId) {
        return ValidatorLib.validatorToIdentifier(validator);
    }

    function getType(ValidatorIdentifier validator) external pure returns (ValidatorType vType) {
        return ValidatorLib.getType(validator);
    }

    function getValidator(ValidatorIdentifier validator) external pure returns (IValidator v) {
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
        (ValidatorMode vMode, ValidatorType vType, ValidatorIdentifier vId) = validatorLib.decode(nonce);
        assertTrue(vMode == MODE_DEFAULT, "vMode != MODE_DEFAULT");
        assertTrue(vType == TYPE_SUDO, "vType != TYPE_VALIDATOR");
    }

    function testDecode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, sequencialNonce)));
        (ValidatorMode vMode, ValidatorType vType, ValidatorIdentifier vId) = validatorLib.decode(nonce);
        assertTrue(vMode == ValidatorMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidatorType.wrap(vtype), "vType != type");
        assertTrue(
            vId == ValidatorIdentifier.wrap(bytes21(abi.encodePacked(vtype, vIdWithoutType))), "vId != vIdWithoutType"
        );
    }

    function testEncode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint16 nonceKey = uint16(bytes2(sequencialNonce));
        uint64 seqNonce = uint64(bytes8(sequencialNonce << 16));
        uint256 encoded = validatorLib.encode(mode, vtype, vIdWithoutType, nonceKey, seqNonce);
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, sequencialNonce)));
        assertEq(bytes32(nonce), bytes32(encoded));
    }

    function testValidatorLib(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint16 nonceKey = uint16(bytes2(sequencialNonce));
        uint64 seqNonce = uint64(bytes8(sequencialNonce << 16));
        uint256 encoded = validatorLib.encode(mode, vtype, vIdWithoutType, nonceKey, seqNonce);

        (ValidatorMode vMode, ValidatorType vType, ValidatorIdentifier vId) = validatorLib.decode(encoded);
        assertTrue(vMode == ValidatorMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidatorType.wrap(vtype), "vType != type");
        assertTrue(
            vId == ValidatorIdentifier.wrap(bytes21(abi.encodePacked(vtype, vIdWithoutType))), "vId != vIdWithoutType"
        );

        IValidator v = validatorLib.getValidator(vId);
        assertEq(address(v), address(vIdWithoutType), "v != vIdWithoutType");

        ValidatorIdentifier vid = validatorLib.validatorToIdentifier(v);
        assertTrue(
            vid == ValidatorIdentifier.wrap(bytes21(abi.encodePacked(TYPE_VALIDATOR, vIdWithoutType))),
            "vid != vIdWithoutType"
        );

        ValidatorType vt = validatorLib.getType(vId);
        assertTrue(vt == ValidatorType.wrap(vtype), "vt != vtype");
    }
}
