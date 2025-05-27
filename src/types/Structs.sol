pragma solidity ^0.8.0;

import "./Types.sol";

struct Install {
    uint256 moduleType;
    address module;
    bytes moduleData;
    bytes internalData;
}

struct Uninstall {
    uint256 moduleType;
    address module;
    bytes data;
}

struct ValidationInfo {
    ValidationType vType;
    address[] policies;
    address signer;
}

struct ValidationStorage {
    ValidationId root;
    mapping(ValidationId vId => ValidationInfo) vInfo;
}
