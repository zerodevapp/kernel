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
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Lib4337} from "src/lib/Lib4337.sol";

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
        bytes32 hash = replay ? Lib4337.chainAgnosticUserOpHash(address(ep), op) : ep.getUserOpHash(op);
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

    function test_deploy_with_call() external unitTest {
        Install[] memory initPkgs = new Install[](0);
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        kernel = Kernel(payable(factory.getECDSAAddress(owner, initPkgs, 1)));
        bytes memory sig = enableSig(0, true, false, pkgs, _rootSignHash);
        Kernel k =
            factory.deployECDSAWithCall(owner, initPkgs, 1, abi.encodeWithSelector(0xa706cd33, false, 0, pkgs, sig));
        assertEq(address(k), address(kernel));
        ValidationInfo memory vInfo = k.validationInfo(
            ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), bytes20(address(newValidator)))))
        );
        assertTrue(vInfo.hook == address(1));
    }
}
