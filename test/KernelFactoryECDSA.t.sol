pragma solidity ^0.8.0;

import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {Install, ValidationInfo} from "src/types/Structs.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {ChainAgnosticHashHelper} from "./utils/ChainAgnosticHashHelper.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract KernelFactoryECDSATest is KernelTestBase {
    function setUp() external {
        ep = EntryPointLib.deploy();

        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        newValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        policy = new MockPolicy();
        signer = new MockSigner();
        hashHelper = new ChainAgnosticHashHelper();
        permissionId = PermissionId.wrap(bytes4(keccak256(abi.encodePacked("Hello world"))));
        vm.txGasPrice(1);
        _initialize();
    }

    address owner;
    uint256 ownerKey;

    function _initialize() internal virtual override {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        Install[] memory initPkgs = new Install[](0);
        kernel = factory.deployECDSA(owner, initPkgs, 0);
        assertEq(address(kernel), address(factory.getECDSAAddress(owner, initPkgs, 0)));
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        view
        override
        returns (bytes memory sig)
    {
        bytes32 hash = replay ? hashHelper.chainAgnosticUserOpHash(address(ep), op) : ep.getUserOpHash(op);
        return _rootSignHash(hash, success);
    }

    function _rootSignHash(bytes32 hash, bool success) internal view override returns (bytes memory sig) {
        if (!success) {
            hash = keccak256(abi.encodePacked(hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function test_deploy() external {
        Install[] memory initPkgs = new Install[](0);
        factory.deployECDSA(owner, initPkgs, 1);
    }

    function test_deploy_existing() external {
        Install[] memory initPkgs = new Install[](0);
        factory.deployECDSA(owner, initPkgs, 0);
    }

    function test_deploy_with_value() external {
        Install[] memory initPkgs = new Install[](0);
        uint256 depositValue = 1 ether;
        vm.deal(address(this), depositValue);
        Kernel k = factory.deployECDSA{value: depositValue}(owner, initPkgs, 2);
        assertEq(address(k).balance, depositValue);
    }

    function test_deploy_existing_with_value() external {
        Install[] memory initPkgs = new Install[](0);
        // First deploy
        factory.deployECDSA(owner, initPkgs, 3);
        // Second deploy with value to same address
        uint256 depositValue = 1 ether;
        vm.deal(address(this), depositValue);
        Kernel k = factory.deployECDSA{value: depositValue}(owner, initPkgs, 3);
        assertEq(address(k).balance, depositValue);
    }

    function test_deploy_invalid_signer() external {
        Install[] memory initPkgs = new Install[](0);
        vm.expectRevert(abi.encodeWithSignature("InvalidSigner()"));
        factory.deployECDSA(address(0), initPkgs, 1);
    }

    function test_get_ecdsa_address() external view {
        Install[] memory initPkgs = new Install[](0);
        address predicted = factory.getECDSAAddress(owner, initPkgs, 0);
        assertEq(predicted, address(kernel));
    }
}
