import "src/core/PermissionManager.sol";
import "forge-std/Test.sol";

contract PermissionTest is Test {
    function testDecode() external {
        uint256 nonce = uint256(bytes32(0));
        (ValidatorMode vMode, ValidatorType vType, ValidatorIdentifier vId) = ValidatorLib.decode(nonce);
        assertTrue(vMode == MODE_DEFAULT, "vMode != MODE_DEFAULT");
        assertTrue(vType == TYPE_SUDO, "vType != TYPE_VALIDATOR");
    }

    function testDecode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, sequencialNonce)));
        (ValidatorMode vMode, ValidatorType vType, ValidatorIdentifier vId) = ValidatorLib.decode(nonce);
        assertTrue(vMode == ValidatorMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidatorType.wrap(vtype), "vType != type");
        assertTrue(vId == ValidatorIdentifier.wrap(bytes21(abi.encodePacked(vtype,vIdWithoutType))), "vId != vIdWithoutType");
    }
    
    function testEncode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint16 nonceKey = uint16(bytes2(sequencialNonce));
        uint64 seqNonce = uint64(bytes8(sequencialNonce << 16));
        uint256 encoded = ValidatorLib.encode(mode, vtype, vIdWithoutType, nonceKey, seqNonce);
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, sequencialNonce)));
        assertEq(bytes32(nonce), bytes32(encoded));
    }
}
