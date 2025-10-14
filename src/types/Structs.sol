pragma solidity ^0.8.0;

import {ValidationId, ValidationType} from "./Types.sol";

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
    address hook;
    address signer;
    address[] policies;
}

struct ValidationStorage {
    ValidationId root;
    mapping(ValidationId vId => ValidationInfo) vInfo;
    mapping(ValidationId vId => mapping(bytes4 selector => bool)) allowed;
}

struct Call {
    address to;
    uint256 value;
    bytes data;
}

struct InstallAndExecute {
    bool replayable;
    uint256 nonce;
    Install[] packages;
    bytes signature;
}
