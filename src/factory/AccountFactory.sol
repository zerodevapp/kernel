// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "./EIP1967Proxy.sol";
import "./MinimalAccount.sol";

contract AccountFactory {
    MinimalAccount public immutable accountTemplate;

    event AccountCreated(address indexed account, address indexed owner, uint256 index);

    constructor(IEntryPoint _entryPoint) {
        accountTemplate = new MinimalAccount(_entryPoint);
    }

    function createAccount(address _owner, uint256 _index) external returns (EIP1967Proxy proxy) {
        bytes32 salt = keccak256(abi.encodePacked(_owner, _index));
        address addr = Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(EIP1967Proxy).creationCode,
                    abi.encode(address(accountTemplate), abi.encodeCall(MinimalAccount.initialize, (_owner)))
                )
            )
        );
        if (addr.code.length > 0) {
            return EIP1967Proxy(payable(addr));
        }
        proxy =
        new EIP1967Proxy{salt: salt}(address(accountTemplate), abi.encodeWithSelector(MinimalAccount.initialize.selector, _owner));
        emit AccountCreated(address(proxy), _owner, _index);
    }

    function getAccountAddress(address _owner, uint256 _index) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(_owner, _index));
        return Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(EIP1967Proxy).creationCode,
                    abi.encode(address(accountTemplate), abi.encodeCall(MinimalAccount.initialize, (_owner)))
                )
            )
        );
    }
}
