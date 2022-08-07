// SPDX-License-Identifier: MIT
// @author Eggshill

pragma solidity ^0.8.4;

import "./WeightedRaffle.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract Factory is Ownable, ReentrancyGuard {
    VRFCoordinatorV2Interface public constant VRF_COORDINATOR =
        VRFCoordinatorV2Interface(0x7a1BaC17Ccc5b313516C5E16fb24f7659aA5ebed);  // mumbai testnet

    address public weightedRaffleImplementation;

    uint64 public subscriptionId;

    event CreateWeightedRaffle(address indexed newRaffleAddress);

    constructor() {
        weightedRaffleImplementation = address(new WeightedRaffle());

        subscriptionId = VRF_COORDINATOR.createSubscription();
    }

    function requestSubscriptionOwnerTransfer(address newOwner) public onlyOwner {
        VRF_COORDINATOR.requestSubscriptionOwnerTransfer(subscriptionId, newOwner);
    }

    function createSubscription() public onlyOwner {
        subscriptionId = VRF_COORDINATOR.createSubscription();
    }

    function createWeightedRaffle(
        uint256 startTime_,
        uint256 endTime_,
        uint256 winnersNumber_,
        address signer_
    ) public payable {
        address clonedWeightedRaffle = Clones.clone(weightedRaffleImplementation);

        VRF_COORDINATOR.addConsumer(subscriptionId, clonedWeightedRaffle);

        WeightedRaffle(clonedWeightedRaffle).initialize(startTime_, endTime_, winnersNumber_, signer_, subscriptionId);

        WeightedRaffle(clonedWeightedRaffle).transferOwnership(msg.sender);

        emit CreateWeightedRaffle(clonedWeightedRaffle);
    }

    function changeImplementation(address newImplementationAddress) public onlyOwner {
        weightedRaffleImplementation = newImplementationAddress;
    }
}
