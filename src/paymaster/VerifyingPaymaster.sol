// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */

import "account-abstraction/core/BasePaymaster.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * A paymaster that uses external service to decide whether to pay for the UserOp.
 * The paymaster trusts an external signer to sign the transaction.
 * The calling user must pass the UserOp to that external signer first, which performs
 * whatever off-chain verification before signing the UserOp.
 * Note that this signature is NOT a replacement for the account-specific signature:
 * - the paymaster checks a signature to agree to PAY for GAS.
 * - the account checks a signature to prove identity and account ownership.
 */
contract VerifyingPaymaster is BasePaymaster, ReentrancyGuard {

    using UserOperationLib for UserOperation;

    address public immutable verifyingSigner;

    uint256 private constant VALID_PAYMASTER_ID_OFFSET = 20;
    uint256 private constant VALID_TIMESTAMP_OFFSET = 52;
    uint256 private constant SIGNATURE_OFFSET = VALID_TIMESTAMP_OFFSET + 64;
    uint256 private constant POSTOP_OVERHEAD_PERCENTAGE = 5; //  5% overhead

    mapping(bytes32 => uint256) private balances;
    mapping(address => bytes32) public userToPaymasterId;

    event Withdrawal(address indexed user, bytes32 indexed paymasterId, uint256 amount);
    event Deposit(address indexed user, bytes32 indexed paymasterId, uint256 amount);
    event BalanceDeducted(bytes32 indexed paymasterId, uint256 amount);


    constructor(IEntryPoint _entryPoint, address _verifyingSigner) BasePaymaster(_entryPoint) Ownable() {
        require(address(_entryPoint).code.length > 0, "Paymaster: passed _entryPoint is not currently a contract");
        require(_verifyingSigner != address(0), "Paymaster: verifyingSigner cannot be address(0)");
        require(_verifyingSigner != msg.sender, "Paymaster: verifyingSigner cannot be the owner");
        verifyingSigner = _verifyingSigner;
    }

    /**
     * return the hash we're going to sign off-chain (and validate on-chain)
     * this method is called by the off-chain service, to sign the request.
     * it is called on-chain from the validatePaymasterUserOp, to validate the signature.
     * note that this signature covers all fields of the UserOperation, except the "paymasterAndData",
     * which will carry the signature itself.
     */
    function getHash(UserOperation calldata userOp, uint48 validUntil, uint48 validAfter, bytes32 paymasterId)
    public view returns (bytes32) {
        // can't use userOp.hash(), since it contains also the paymasterAndData itself.
        // return keccak256(
        //     abi.encode(
        //         userOp.getSender(),
        //         userOp.nonce,
        //         calldataKeccak(userOp.initCode),
        //         calldataKeccak(userOp.callData),
        //         userOp.callGasLimit,
        //         userOp.verificationGasLimit,
        //         userOp.preVerificationGas,
        //         userOp.maxFeePerGas,
        //         userOp.maxPriorityFeePerGas,
        //         block.chainid,
        //         paymasterId,
        //         address(this),
        //         validUntil,
        //         validAfter
        //     )
        // );
        
        bytes memory firstHalf = abi.encode(
            userOp.getSender(),
            userOp.nonce,
            calldataKeccak(userOp.initCode),
            calldataKeccak(userOp.callData),
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas
        );

        // Second half encoding
        bytes memory secondHalf = abi.encode(
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            block.chainid,
            paymasterId,
            address(this),
            validUntil,
            validAfter
        );

        // Combine the two halves and compute the final hash
        return keccak256(abi.encodePacked(firstHalf, secondHalf));
    }

    /**
     * verify our external signer signed this request.
     * the "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:20] : address(this)
     * paymasterAndData[20:84] : abi.encode(validUntil, validAfter)
     * paymasterAndData[84:] : signature
     */
    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32 /*userOpHash*/, uint256 /*requiredPreFund*/)
    internal view override returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature, bytes32 paymasterId) = parsePaymasterAndData(userOp.paymasterAndData);
        // Only support 65-byte signatures, to avoid potential replay attacks.
        require(signature.length == 65, "Paymaster: invalid signature length in paymasterAndData");
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, paymasterId));

        context = abi.encode(paymasterId);

        // don't revert on signature failure: return SIG_VALIDATION_FAILED
        if (verifyingSigner != ECDSA.recover(hash, signature)) {
            return (context, _packValidationData(true, validUntil, validAfter));
        }

        // no need for other on-chain validation: entire UserOp should have been checked
        // by the external service prior to signing it.
        return (context, _packValidationData(false, validUntil, validAfter));

    }

    function _postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) internal virtual override {
        bytes32 paymasterId = abi.decode(context, (bytes32));
        uint256 overhead = (actualGasCost * POSTOP_OVERHEAD_PERCENTAGE) / 100;
        uint256 totalDeduction = actualGasCost + overhead;
        require(balances[paymasterId] >= totalDeduction, "Paymaster: Insufficient balance");
        balances[paymasterId] -= totalDeduction;
        emit BalanceDeducted(paymasterId, totalDeduction);
    }

    function parsePaymasterAndData(bytes calldata paymasterAndData)
        internal pure returns(uint48 validUntil, uint48 validAfter, bytes calldata signature, bytes32 paymasterId) {
        // Extracting paymasterId from the start of paymasterAndData
        paymasterId = bytes32(paymasterAndData[VALID_PAYMASTER_ID_OFFSET:VALID_TIMESTAMP_OFFSET]);

        // Extracting validUntil and validAfter, assuming they follow paymasterId
        (validUntil, validAfter) = abi.decode(paymasterAndData[VALID_TIMESTAMP_OFFSET:SIGNATURE_OFFSET], (uint48, uint48));
        
        // Extracting signature, assuming it follows validUntil and validAfter
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    function depositTo(bytes32 paymasterId) public payable nonReentrant{
        require(msg.value > 0, "Deposit amount must be greater than 0");
        userToPaymasterId[msg.sender] = paymasterId;
        balances[paymasterId] += msg.value;
        entryPoint.depositTo{value: msg.value}(address(this));
        emit Deposit(msg.sender, paymasterId, msg.value);
    }

    function deposit() public payable virtual override {
        revert("use depositTo");
    }

    function withdraw(address payable withdrawAddress, uint256 amount) public nonReentrant {
        require(withdrawAddress != address(0), "invalid address");
        bytes32 paymasterId = userToPaymasterId[msg.sender];
        require(paymasterId != bytes32(0), "User not registered");
        require(balances[paymasterId] >= amount, "Insufficient balance");

        balances[paymasterId] -= amount;
        entryPoint.withdrawTo(payable(withdrawAddress), amount);
        emit Withdrawal(msg.sender, paymasterId, amount);
    }

    function getBalance(bytes32 paymasterId) public view returns (uint256) {
        return balances[paymasterId];
    }


    function renounceOwnership() public override view onlyOwner {
        revert("Paymaster: renouncing ownership is not allowed");
    }

    function transferOwnership(address newOwner) public override onlyOwner {
        require(newOwner != address(0), "Paymaster: owner cannot be address(0)");
        require(newOwner != verifyingSigner, "Paymaster: owner cannot be the verifyingSigner");
        _transferOwnership(newOwner);
    }

    receive() external payable {
        // use address(this).balance rather than msg.value in case of force-send
        (bool callSuccess, ) = payable(address(entryPoint)).call{value: address(this).balance}("");
        require(callSuccess, "Deposit failed");
    }


}