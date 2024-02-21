// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "account-abstraction/core/BasePaymaster.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/UserOperation.sol";
import "account-abstraction/core/EntryPoint.sol";
import "solady/utils/SafeTransferLib.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


/// @title ERC20Paymaster
contract ERC20Paymaster is BasePaymaster {
    using SafeERC20 for IERC20;

    uint256 public constant priceDenominator = 1e6;
    uint256 public constant REFUND_POSTOP_COST = 40000; // Estimated gas cost for refunds

    IERC20 public immutable token;
    uint256 public immutable tokenDecimals;
    AggregatorV3Interface public immutable tokenOracle;
    AggregatorV3Interface public immutable nativeAssetOracle;

    uint192 public previousPrice;
    uint32 public priceMarkup;
    uint32 public priceUpdateThreshold;

    event ConfigUpdated(uint32 priceMarkup, uint32 updateThreshold);
    event UserOperationSponsored(address indexed user, uint256 actualTokenNeeded, uint256 actualGasCost);

    constructor(
        IERC20Metadata _token,
        IEntryPoint _entryPoint,
        AggregatorV3Interface _tokenOracle,
        AggregatorV3Interface _nativeAssetOracle,
        address _owner
    ) BasePaymaster(_entryPoint) {
        token = _token;
        tokenOracle = _tokenOracle;
        nativeAssetOracle = _nativeAssetOracle;
        priceMarkup = 110e4; // 110%
        priceUpdateThreshold = 25e3; // 2.5%
        tokenDecimals = 10 ** _token.decimals();
        transferOwnership(_owner);
    }

    function updateConfig(uint32 _priceMarkup, uint32 _updateThreshold) external onlyOwner {
        require(_priceMarkup <= 120e4 && _priceMarkup >= 1e6, "Invalid price markup");
        require(_updateThreshold <= 1e6, "Invalid update threshold");
        priceMarkup = _priceMarkup;
        priceUpdateThreshold = _updateThreshold;
        emit ConfigUpdated(_priceMarkup, _updateThreshold);
    }

    function withdrawToken(address to, uint256 amount) external onlyOwner {
        token.safeTransfer(to, amount);
    }

    function updatePrice() external {
        uint192 tokenPrice = fetchPrice(tokenOracle);
        uint192 nativeAssetPrice = fetchPrice(nativeAssetOracle);
        previousPrice = nativeAssetPrice * uint192(tokenDecimals) / tokenPrice;
    }


    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 requiredPreFund)
        internal
        override
        returns (bytes memory context, uint256 validationResult)
    {
        // Ensure the price has been updated and is not zero
        require(previousPrice > 0, "Price not updated");


        // Extract the maximum token amount the user agrees to spend from userOp.paymasterAndData
        // This requires encoding the max token amount in paymasterAndData during the user operation setup
        uint256 userMaxTokenAmount;
        if (userOp.paymasterAndData.length > 20) {
            userMaxTokenAmount = abi.decode(userOp.paymasterAndData[20:], (uint256));
        } else {
            revert("Invalid paymasterAndData length");
        }

        // Calculate the required token amount for the gas pre-funding
        uint256 tokenAmountRequired = calculateTokenAmount(requiredPreFund, userOp.maxFeePerGas);

        // Ensure the user has agreed to spend enough tokens to cover the transaction
        require(userMaxTokenAmount >= tokenAmountRequired, "Insufficient pre-fund token amount");
        SafeTransferLib.safeTransferFrom(address(token), userOp.sender, address(this), tokenAmountRequired);
        // Prepare the context to be used in _postOp for refund calculations
        context = abi.encode(tokenAmountRequired, userOp.sender);

        // Return the context and the gas limit for execution
        // `gasLimit` here can be the `requiredPreFund` or a custom value based on your contract's logic
        validationResult = 0;
    }

    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        if (mode == PostOpMode.postOpReverted) return;

        updatePriceIfNeeded();
        uint256 actualTokenNeeded = calculateTokenAmount(actualGasCost, tx.gasprice);
        uint256 providedTokenAmount = uint256(bytes32(context[0:32]));
        address user = address(bytes20(context[44:]));

        if (providedTokenAmount > actualTokenNeeded) {
            uint256 refundAmount = providedTokenAmount - actualTokenNeeded;
            SafeTransferLib.safeTransfer(
                address(token),
                user,
                refundAmount
            );
        }

        emit UserOperationSponsored(user, actualTokenNeeded, actualGasCost);
    }

   
    function fetchPrice(AggregatorV3Interface _oracle) internal view returns (uint192 price) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = _oracle.latestRoundData();
        require(answer > 0, "PP-ERC20: Chainlink price <= 0");
        require(updatedAt >= block.timestamp - 2 days, "PP-ERC20: Stale price");
        require(answeredInRound == roundId, "PP-ERC20: Stale round");

        // First, cast 'answer' to 'uint256', then cast it to 'uint192'
        uint256 answerUnsigned = uint256(answer);
        require(answerUnsigned <= type(uint192).max, "PP-ERC20: Price exceeds uint192 max value");
        price = uint192(answerUnsigned);
    }


    function updatePriceIfNeeded() internal {
        uint192 tokenPrice = fetchPrice(tokenOracle);
        uint192 nativeAssetPrice = fetchPrice(nativeAssetOracle);
        uint192 currentPrice = nativeAssetPrice * uint192(tokenDecimals) / tokenPrice;

        if (priceChangedSignificantly(currentPrice)) {
            previousPrice = currentPrice;
        }
    }

    function priceChangedSignificantly(uint192 currentPrice) internal view returns (bool) {
        uint256 changePercent = currentPrice * priceDenominator / previousPrice;
        return changePercent > priceDenominator + priceUpdateThreshold || changePercent < priceDenominator - priceUpdateThreshold;
    }

    function calculateTokenAmount(uint256 gasCost, uint256 gasPrice) internal view returns (uint256) {
        return (gasCost + REFUND_POSTOP_COST * gasPrice) * priceMarkup * previousPrice / (1e18 * priceDenominator);
    }
}
