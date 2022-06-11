// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./whitelistRaffle-largeScale.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract Factory is Ownable, ReentrancyGuard {
    VRFCoordinatorV2Interface public constant VRF_COORDINATOR =
        VRFCoordinatorV2Interface(0x6A2AAd07396B36Fe02a22b33cf443582f682c82f);

    address public weightedRaffleImplementation;

    uint64 public subscriptionId;

    event CreateNFT(address indexed nftAddress);

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
        uint256 winnersLength_,
        address signer_
    ) public payable {
        address clonedWeightedRaffle = Clones.clone(weightedRaffleImplementation);

        VRF_COORDINATOR.addConsumer(subscriptionId, clonedWeightedRaffle);

        WeightedRaffle(clonedWeightedRaffle).initialize(startTime_, endTime_, winnersLength_, signer_, subscriptionId);

        WeightedRaffle(clonedWeightedRaffle).transferOwnership(msg.sender);

        emit CreateNFT(clonedWeightedRaffle);
    }

    function changeImplementation(address newImplementationAddress) public onlyOwner {
        weightedRaffleImplementation = newImplementationAddress;
    }
}
