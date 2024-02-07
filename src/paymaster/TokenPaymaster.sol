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

/// @title PimlicoERC20Paymaster
/// @notice An ERC-4337 Paymaster contract by Pimlico which sponsors gas fees in exchange for ERC20 tokens using Chainlink for price feeds.
contract PimlicoERC20Paymaster is BasePaymaster {
    using SafeTransferLib for IERC20;

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
        require(previousPrice != 0, "Price not set");
        uint256 tokenAmount = calculateTokenAmount(requiredPreFund, userOp.maxFeePerGas);
        SafeTransferLib.safeTransferFrom(address(token), userOp.sender, address(this), tokenAmount);
        context = abi.encodePacked(tokenAmount, userOp.sender);
        validationResult = 0;
    }

    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        if (mode == PostOpMode.postOpReverted) return;

        updatePriceIfNeeded();
        uint256 actualTokenNeeded = calculateTokenAmount(actualGasCost, tx.gasprice);
        uint256 providedTokenAmount = uint256(bytes32(context[0:32]));
        address user = address(bytes20(context[32:52]));

        if (providedTokenAmount > actualTokenNeeded) {
            uint256 refundAmount = providedTokenAmount - actualTokenNeeded;
            token.safeTransfer(user, refundAmount);
        }

        emit UserOperationSponsored(user, actualTokenNeeded, actualGasCost);
    }

    function fetchPrice(AggregatorV3Interface _oracle) internal view returns (uint192 price) {
        (,int256 answer,,uint256 updatedAt,) = _oracle.latestRoundData();
        require(answer > 0 && updatedAt >= block.timestamp - 2 days, "Invalid price data");
        price = uint192(answer);
    }

    function updatePriceIfNeeded() internal {
        uint192 tokenPrice = fetchPrice(tokenOracle);
        uint192 nativeAssetPrice = fetchPrice(nativeAssetOracle);
        uint192 currentPrice = nativeAssetPrice * uint192(tokenDecimals) / tokenPrice;

        if (priceChangedSignificantly(currentPrice, previousPrice)) {
            previousPrice = currentPrice;
        }
    }

    function priceChangedSignificantly(uint192 currentPrice, uint192 previousPrice) internal view returns (bool) {
        uint256 changePercent = currentPrice * priceDenominator / previousPrice;
        return changePercent > priceDenominator + priceUpdateThreshold || changePercent < priceDenominator - priceUpdateThreshold;
    }

    function calculateTokenAmount(uint256 gasCost, uint256 gasPrice) internal view returns (uint256) {
        return (gasCost + REFUND_POSTOP_COST * gasPrice) * priceMarkup * previousPrice / (1e18 * priceDenominator);
    }
}
