pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelHelper} from "src/KernelHelper.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockERC721} from "./mock/MockERC721.sol";
import {MockERC1155} from "./mock/MockERC1155.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {MockContractETH} from "./mock/MockContractETH.sol";
import {MockKernel} from "./mock/MockKernel.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {console} from "forge-std/console.sol";
import {Received} from "src/types/Events.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationMode} from "src/types/Types.sol";

abstract contract KernelTestBase is Test {
    IEntryPoint ep;
    KernelFactory factory;
    IValidator rootValidator;
    bytes rootValidatorData;
    MockValidator newValidator;
    Kernel kernel;
    MockCallee callee;
    MockFallback mockFallback;
    address executor;
    address payable beneficiary;
    MockPolicy policy;
    MockSigner signer;
    bytes20 permissionId;
    uint256 permissionRevertIndex;
    KernelHelper helper;

    bool is7702;
    bool isImmutable;

    modifier unitTest() {
        vm.startPrank(address(ep));
        _;
        vm.stopPrank();
    }

    modifier unitTestExecutor() {
        vm.startPrank(address(executor));
        _;
        vm.stopPrank();
    }

    modifier entryPointTest() {
        _;
    }

    function _initialize() internal virtual;

    function _rootSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        virtual
        returns (bytes memory sig)
    {
        MockValidator(address(rootValidator)).sudoSetSuccess(success);
        return hex"";
    }

    function _rootSignHash(bytes32 hash, bool success) internal virtual returns (bytes memory sig) {
        if (success) {
            MockValidator(address(rootValidator)).sudoSetValidSig(hex"");
        }
        return hex"";
    }

    function _validatorSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        virtual
        returns (bytes memory sig)
    {
        newValidator.sudoSetSuccess(success);
        return hex"";
    }

    function _validatorSignHash(bytes32 hash, bool success) internal virtual returns (bytes memory sig) {
        if (success) {
            newValidator.sudoSetValidSig(hex"");
        }
        return hex"";
    }

    function _permissionSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        virtual
        returns (bytes memory sig)
    {
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        if (success || permissionRevertIndex != 0) {
            policy.sudoSetValidSig(address(kernel), permissionId, hex"dead");
        }
        if (success || permissionRevertIndex != 1) {
            signer.sudoSetValidSig(address(kernel), permissionId, hex"beef");
        }

        return abi.encode(signatures);
    }

    function _permissionSignHash(bytes32 hash, bool success) internal virtual returns (bytes memory sig) {
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        if (success || permissionRevertIndex != 0) {
            policy.sudoSetPass(address(kernel), permissionId, true);
        }
        if (success || permissionRevertIndex != 1) {
            signer.sudoSetPass(address(kernel), permissionId, true);
        }

        return abi.encode(signatures);
    }

    function enableSig(
        uint256 nonce,
        bool enableSuccess,
        bool replayable,
        Install[] memory packages,
        function(bytes32, bool) internal returns(bytes memory) signEnable
    ) internal returns (bytes memory sig) {
        bytes32 digest = helper.installDigest(address(kernel), replayable, nonce, packages);
        MockKernel mockKernel = new MockKernel(ep);

        if (!is7702) {
            //vm.store(address(kernel), ERC1967_IMPLEMENTATION_SLOT, bytes32(uint256(uint160(address(mockKernel)))));
            //assertEq(MockKernel(payable(address(kernel))).installDigest(replayable, nonce, packages), digest);
            //vm.store(address(kernel), ERC1967_IMPLEMENTATION_SLOT, bytes32(uint256(uint160(address(factory.template())))));
        }
        return signEnable(digest, enableSuccess);
    }

    function encodeEnableValidatorSignature(
        bytes4 selector,
        uint256 nonce,
        bool enableSuccess,
        bool replayable,
        function(bytes32, bool) internal returns(bytes memory) signEnable,
        bytes memory userOpSig
    ) internal returns (bytes memory sig) {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(newValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(address(0), selector)
        });
        sig = abi.encode(
            uint256(0), packages, enableSig(nonce, enableSuccess, replayable, packages, signEnable), userOpSig
        );
    }

    function encodeEnablePermissionSignature(
        bytes4 selector,
        uint256 nonce,
        bool enableSuccess,
        bool replayable,
        function(bytes32, bool) internal returns(bytes memory) signEnable,
        bytes memory userOpSig
    ) internal returns (bytes memory sig) {
        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), selector)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });

        sig = abi.encode(
            uint256(0), packages, enableSig(nonce, enableSuccess, replayable, packages, signEnable), userOpSig
        );
    }

    function encodeNonce(bool replayableUserOp, bool enableFlag, bool replayableEnable, bytes1 vType, bytes20 vId)
        internal
        returns (uint256 nonce)
    {
        uint8 uMode = 0;
        if (replayableUserOp) {
            uMode += 2 ** 6;
        }
        if (enableFlag) {
            uMode += 2 ** 3;
        }
        if (replayableEnable) {
            uMode += 2 ** 2;
        }
        ValidationMode vMode = ValidationMode.wrap(bytes1(uMode));
        uint192 key = uint192(bytes24(abi.encodePacked(uMode, vType, vId, bytes2(0x00))));
        return ep.getNonce(address(kernel), key);
    }

    function test_codesize() external {
        vm.skip(true);
        address implementation = address(factory.UUPS());
        console.log("Code size :", implementation.code.length);
        require(implementation.code.length <= 24576, "Code too big");
        console.log("space left :", 24576 - implementation.code.length);
    }

    function test_receive_eth() external {
        address sender = makeAddr("Sender");
        address payable k = payable(address(kernel));
        vm.deal(sender, 1e18);
        // if not through kernel, only <address>call{value} works
        vm.startPrank(sender);
        vm.expectEmit(k);
        emit Received(sender, uint256(1));
        (bool success,) = k.call{value: 1}(hex"");
        require(success);
        vm.stopPrank();

        MockContractETH mock = new MockContractETH();
        vm.deal(address(mock), 1e18);
        // if done through kernel, accepts both transfer and send
        vm.startPrank(address(ep));
        vm.expectEmit(k);
        emit Received(address(mock), uint256(1));
        kernel.execute(
            bytes32(0),
            abi.encodePacked(
                address(mock), uint256(0), abi.encodeWithSelector(MockContractETH.useTransfer.selector, k, uint256(1))
            )
        );
        vm.expectEmit(k);
        emit Received(address(mock), uint256(1));
        kernel.execute(
            bytes32(0),
            abi.encodePacked(
                address(mock), uint256(0), abi.encodeWithSelector(MockContractETH.useSend.selector, k, uint256(1))
            )
        );
        vm.stopPrank();
    }

    function test_receive_erc721() external {
        MockERC721 mock = new MockERC721();
        address sender = makeAddr("Sender");

        mock.mint(sender, 1);

        vm.prank(sender);
        mock.safeTransferFrom(sender, address(kernel), 1);

        mock.safeMint(address(kernel), 2);
    }

    function test_receive_erc1155() external {
        MockERC1155 mock = new MockERC1155();
        address sender = makeAddr("Sender");

        mock.mint(sender, 1, 1, hex"deadbeef");
        vm.prank(sender);
        mock.safeTransferFrom(sender, address(kernel), 1, 1, hex"deadbeef");

        mock.mint(address(kernel), 1, 1, hex"deadbeef");

        mock.mint(sender, 2, 4, hex"deadbeef");
        mock.mint(sender, 3, 5, hex"deadbeef");
        uint256[] memory ids = new uint256[](2);
        ids[0] = 2;
        ids[1] = 3;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 2;
        amounts[1] = 3;
        vm.prank(sender);
        mock.safeBatchTransferFrom(sender, address(kernel), ids, amounts, hex"deadbeef");

        mock.batchMint(address(kernel), ids, amounts, hex"deadbeef");
    }
}
