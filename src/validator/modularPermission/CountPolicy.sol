import "./IPolicy.sol";
import "src/common/Types.sol";

struct Count {
    uint128 current;
    uint128 allowed;
}

contract CountPolicy is IPolicy {
    address public immutable permissionValidator;

    constructor(address _permissionValidator) {
        permissionValidator = _permissionValidator;
    }

    mapping(bytes32 permissionId => mapping(address kernel => Count)) public counts;

    function registerPolicy(address kernel, bytes32 permissionId, bytes calldata policyData)
        external
        payable
        override
    {
        require(policyData.length == 16, "Invalid policy data");
        uint128 allowed = uint128(bytes16(policyData[0:16]));
        counts[permissionId][kernel].allowed = allowed;
    }

    function validatePolicy(
        address kernel,
        bytes32 permissionId,
        UserOperation calldata userOp,
        bytes calldata proofAndSig
    ) external payable override returns (ValidationData, uint256 consumedSignatureLength) {
        Count storage count = counts[permissionId][kernel];
        require(count.current < count.allowed, "Permission revoked");
        count.current++;
        return (packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0)), 0);
    }

    function validateSignature(
        address kernel,
        address caller,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view override returns (ValidationData, uint256 consumedSignatureLength) {
        revert("not implemented");
    }
}
