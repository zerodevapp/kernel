
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

