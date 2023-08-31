// SPDX-License-Identifier: MIT

//forge test --match-contract KernelMultiOwnedPatchTest1inch
//find lib/limit-order-protocol/contracts -name "*.sol" -exec sed -i '' 's/0.8.17/0.8.19/g' {} \;
pragma solidity ^0.8.0;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {ECDSA as OneInchECDSA} from "@1inch/solidity-utils/contracts/libraries/ECDSA.sol";
import "src/factory/MultiECDSAFactoryPatch.sol";
import "src/Kernel.sol";
import "src/validator/MultiECDSAValidatorNew.sol";
import "src/test/TestValidator.sol";
import "src/test/TestExecutor.sol";
import "src/test/TestERC721.sol";
import "src/test/TestERC20.sol";
import "@1inch/solidity-utils/contracts/interfaces/IWETH.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import "limit-order-protocol/LimitOrderProtocol.sol";
import "limit-order-protocol/OrderLib.sol";
import {ERC4337Utils, KernelTestBase} from "./utils/ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract KernelMultiOwnedPatchTest1inch is KernelTestBase {
    address secondOwner;
    uint256 secondOwnerKey;
    MultiECDSAFactoryPatch newFactory;
    MultiECDSAValidatorNew multiECDSAValidatorNew;
    address kernelImplementation;

    LimitOrderProtocol limitOrderProtocol;
    TestERC20 usdt;
    TestERC20 usdc;

    function setUp() public {
        _initialize();

        kernelImplementation = address(new Kernel(entryPoint));
        multiECDSAValidatorNew = new MultiECDSAValidatorNew();
        newFactory = new MultiECDSAFactoryPatch(
            factoryOwner,
            entryPoint,
            kernelImplementation,
            multiECDSAValidatorNew
        );

        vm.deal(address(factoryOwner), 1e30);
        vm.startPrank(factoryOwner);
        newFactory.setImplementation(kernelImplementation, true);

        (secondOwner, secondOwnerKey) = makeAddrAndKey("secondOwner");
        address[] memory owners = new address[](2);
        owners[0] = owner;
        owners[1] = secondOwner;
        newFactory.setOwners(owners);
        newFactory.addStake{value: 1}(1);
        vm.stopPrank();

        limitOrderProtocol = new LimitOrderProtocol(
            IWETH(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270)
        );

        usdc = TestERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);

        usdt = TestERC20(0xc2132D05D31c914a87C6611C10748AEb04B58e8F);

        // factory = KernelFactory(address(newFactory));
        // _setAddress();
    }

    function test1inch() external {
        address proxy = newFactory.createAccount(2);

        vm.startPrank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.transfer(address(this), 2);
        vm.stopPrank();
        assertEq(usdc.balanceOf(address(this)), 2);

        vm.startPrank(0x0639556F03714A74a5fEEaF5736a4A64fF70D206);
        usdt.transfer(proxy, 2);
        vm.stopPrank();
        assertEq(usdt.balanceOf(proxy), 2);

        vm.startPrank(proxy);
        usdt.approve(address(limitOrderProtocol), 2);
        vm.stopPrank();

        OrderLib.Order memory order = createOrder(
            1,
            address(usdc),
            address(usdt),
            proxy,
            address(0),
            address(0),
            1,
            1,
            0x4000000000000000000000000000000000000000000000000000000000000000,
            hex""
        );

        bytes32 orderHash = this.getOrderHash(order);

        bytes memory signature = signHash(orderHash, proxy);

        limitOrderProtocol.fillOrder(order, signature, hex"", 1, 1, 0);
    }

    function getOrderHash(
        OrderLib.Order calldata order
    ) public view returns (bytes32) {
        return OrderLib.hash(order, limitOrderProtocol.DOMAIN_SEPARATOR());
    }

    function createOrder(
        uint256 salt,
        address makerAsset,
        address takerAsset,
        address maker,
        address receiver,
        address allowedSender,
        uint256 makingAmount,
        uint256 takingAmount,
        uint256 offsets,
        bytes memory interactions
    ) public pure returns (OrderLib.Order memory) {
        OrderLib.Order memory newOrder = OrderLib.Order({
            salt: salt,
            makerAsset: makerAsset,
            takerAsset: takerAsset,
            maker: maker,
            receiver: receiver,
            allowedSender: allowedSender,
            makingAmount: makingAmount,
            takingAmount: takingAmount,
            offsets: offsets,
            interactions: interactions
        });

        return newOrder;
    }

    function getInitializeData() internal view returns (bytes memory) {
        return
            abi.encodeWithSelector(
                KernelStorage.initialize.selector,
                defaultValidator,
                abi.encodePacked(factory)
            );
    }

    function signUserOp(
        UserOperation memory op
    ) internal view returns (bytes memory) {
        return
            abi.encodePacked(
                bytes4(0x00000000),
                entryPoint.signUserOpHash(vm, ownerKey, op)
            );
    }

    function signHash(
        bytes32 hash,
        address kernel_
    ) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ownerKey,
            ECDSA.toEthSignedMessageHash(
                keccak256(abi.encodePacked(hash, kernel_))
            )
        );
        return abi.encodePacked(r, s, v);
    }
}
