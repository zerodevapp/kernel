// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./KernelFactory.sol";
import "src/validator/MultiECDSAValidator.sol";
import "src/interfaces/IAddressBook.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MultiECDSAKernelFactory is IAddressBook, Ownable {
    KernelFactory public immutable singletonFactory;
    MultiECDSAValidator public immutable validator;
    IEntryPoint public immutable entryPoint;

    address[] public owners;

    constructor(KernelFactory _singletonFactory, MultiECDSAValidator _validator, IEntryPoint _entryPoint) {
        singletonFactory = _singletonFactory;
        validator = _validator;
        entryPoint = _entryPoint;
    }

    function setOwners(address[] calldata _owners) external onlyOwner {
        owners = _owners;
    }

    function getOwners() external view override returns(address[] memory) {
        return owners;
    }

    function createAccount(uint256 _index) external returns (EIP1967Proxy proxy) {
        bytes memory data = abi.encodePacked(address(this));
        proxy = singletonFactory.createAccount(validator, data, _index);
    }

    function getAccountAddress(uint256 _index) public view returns (address) {
        bytes memory data = abi.encodePacked(address(this));
        return singletonFactory.getAccountAddress(validator, data, _index);
    }

    /**
     * add a deposit for this factory, used for paying for transaction fees
     */
    function deposit() public payable {
        entryPoint.depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }
    /**
     * add stake for this factory.
     * This method can also carry eth value to add to the current stake.
     * @param unstakeDelaySec - the unstake delay for this factory. Can only be increased.
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{value : msg.value}(unstakeDelaySec);
    }

    /**
     * return current factory's deposit on the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * unlock the stake, in order to withdraw it.
     * The factory can't serve requests once unlocked, until it calls addStake again
     */
    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    /**
     * withdraw the entire factory's stake.
     * stake must be unlocked first (and then wait for the unstakeDelay to be over)
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }
}
