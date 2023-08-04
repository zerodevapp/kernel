pragma solidity ^0.8.0;

import "src/KernelFactory.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

// A sample ERC721 contract
contract SampleNFT is ERC721 {
    uint256 public tokenId;

    constructor() ERC721("SampleNFT", "SNFT") {}

    // Anyone can mint an NFT for anyone
    function mint(address _to) public {
        _safeMint(_to, tokenId++);
    }
}

contract DeployNFT is Script {
    address DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        (bool success, bytes memory ret) = DETERMINISTIC_DEPLOYER.call(abi.encodePacked(bytes32(0),type(SampleNFT).creationCode));
        if(!success) {
            console.log("deploy failed");
            revert(string(ret));
        }
        console.log("nft deployed at %s", address(bytes20(ret)));
        vm.stopBroadcast();
    }
}

