// SPDX-License-Identifier: MIT
// @author Eggshill

pragma solidity ^0.8.4;

import "./utils/ContextMixin.sol";
import "./utils/NativeMetaTransaction.sol";
import "./utils/VRFConsumerBaseV2Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@prb/math/contracts/PRBMathSD59x18.sol";

error NotRaffleTime();
error WeightIsZero();
error RepeatedRequest();
error InvalidSignature();
error AlreadyInReservior();
error NotListed();
error NoWinner();
error AlreadyStart();
error AlreadyEnd();
error IncorrectTime();
error ZeroAddress();

/// @title weighted raffle with reservior sampling
/// @author Eggshill
contract WeightedRaffle is VRFConsumerBaseV2Upgradeable, NativeMetaTransaction, OwnableUpgradeable, ContextMixin {
    /// @dev using PRBMathUD60x18 for uint256;
    using PRBMathSD59x18 for int256;
    using ECDSAUpgradeable for bytes32;

    VRFCoordinatorV2Interface public constant VRF_COORDINATOR =
        VRFCoordinatorV2Interface(0x7a1BaC17Ccc5b313516C5E16fb24f7659aA5ebed);
    bytes32 public constant KEY_HASH = 0x4b09e658ed251bcafeebbc69400383d49f344ace09b9576fe248bb02c003fe9f; //mumbai testnet
    
    /// @notice lowest ranked winner in reservoir
    /// @dev in the ranged of 0 to winnerSize-1
    uint256 public lowestWinnerIndex;

    /// @notice worst weightedRandomKey in reservior
    /// @dev bigger weightedRandomKey means smaller probablity to win
    uint256 public maxWeightedRandomKey; 

    uint256 public startTime;
    uint256 public endTime;

    /// @notice Number of winners in this raffle.
    /// @dev Also the size of reservoir, require greater than zero.
    uint256 public winnersNumber;

    /// @notice Signer of trusted source of weight.
    address public signer;

    /// @notice Array of winners in reservior.
    address[] public winners;

    struct RequestConfig {
        bytes32 keyHash;
        uint64 subId;
        uint32 callbackGasLimit;
        uint16 requestConfirmations;
        uint32 numWords;
    }
    RequestConfig public s_requestConfig;

    mapping(uint256 => address) private _requestIdToAddress;
    mapping(address => uint256) private _addressToWeight;

    /// @notice WeightedRandomKey of user.
    mapping(address => uint256) public addressToKey;

    /// @notice User's index in the array of winners.
    /// @dev In the range of 1 to winnersNumber.
    mapping(address => uint256) public addressToIndex;

    // Emit all events which changes varibles of reservior for off-chain verification.
    event Requested(address indexed newAddress, uint256 weight, uint256 requestID);
    event FillReservior(
        address indexed newAddress,
        uint256 addressToKey,
        uint256 reserviorHeight,
        address indexed lowestWinner,
        uint256 maxWeightedRandomKey,
        uint256 lowestWinnerIndex
    );
    event Fullfilled(address indexed newAddress, int256 randomSeed, uint256 weightedRandomKey);
    event UpdateReservior(
        address indexed lowestWinner, 
        uint256 lowestWinnerIndex, 
        uint256 maxWeightedRandomKey
    );
    event Updated(address indexed waitlistAddress, uint256 addressToIndex);
    event ExitRaffle(address indexed listedAddress, uint256 reserviorHeight);

    function initialize(
        uint256 startTime_,
        uint256 endTime_,
        uint256 winnersNumber_,
        address signer_,
        uint64 subId_
    ) public initializer {
        __Ownable_init_unchained();
        __VRFConsumerBaseV2_init(address(VRF_COORDINATOR));
        _initializeEIP712('WeightedRaffle');

        startTime = startTime_;
        endTime = endTime_;
        winnersNumber = winnersNumber_;
        signer = signer_;

        s_requestConfig = RequestConfig(
            KEY_HASH,
            subId_,
            2500000, //callbackGasLimit
            3, //requestConfirmations
            1 //numWords,
        );
    }

    /// @dev This is used instead of msg.sender as transactions won't be sent by the original token owner, but by OpenSea.
    function _msgSender() internal view override returns (address sender) {
        return ContextMixin.msgSender();
    }

    /// @notice Drawing of raffle
    function requestRandomWords(
        uint256 weight,
        string calldata salt,
        bytes calldata signature
    ) external {
        if (!isRaffleTime()) revert NotRaffleTime();
        // Weight must be greator than 0
        if (weight == 0) revert WeightIsZero();
        // Every address can only draw once, addressToWeight or addressToKey is only initialized once
        if (_addressToWeight[_msgSender()] != 0 || addressToKey[_msgSender()] != 0) revert RepeatedRequest();

        // Verify the signature to ensure weight coming from trusted source
        if (!verifySignature(salt, _msgSender(), weight, signature)) revert InvalidSignature();

        RequestConfig memory rc = s_requestConfig;
        uint256 requestId = VRF_COORDINATOR.requestRandomWords(
            rc.keyHash,
            rc.subId,
            rc.requestConfirmations,
            rc.callbackGasLimit,
            rc.numWords
        );

        // Return the requestId to the requester.
        _requestIdToAddress[requestId] = _msgSender();
        _addressToWeight[_msgSender()] = weight;

        emit Requested(_msgSender(), weight, requestId);
    }

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
        // Weighted random sampling, solidity adapted A-RES algorithm
        // https://en.wikipedia.org/wiki/Reservoir_sampling#Algorithm_A-Res
        address _newAddress = _requestIdToAddress[requestId];
        int256 randomSeed = int256(randomWords[0] % 1e18);
        uint256 _weightedRandomKey;

        /// In A-RES algorithm, the probablity equals to log(rand(0, 1)) / weight
        if (randomSeed == 0)
            _weightedRandomKey = type(uint256).max; // log(0) = infinity
        else
            _weightedRandomKey = uint256(-randomSeed.log2()) / _addressToWeight[_newAddress]; 

        // _weightedRandomKey must be greater than 0 to identity the address being waitlisted
        // Prevent edge case of _weightedRandomKey == 0 when calculation result exceeding precision
        if (_weightedRandomKey == 0) {
            unchecked {
                _weightedRandomKey = _weightedRandomKey + 1;
            }
        }

        addressToKey[_newAddress] = _weightedRandomKey; // add into waitlist for updating reservior later
        // Prioritize filling unfilled reservoirs
        if (winners.length < winnersNumber)
            _fillReservior(_newAddress);

        delete _requestIdToAddress[requestId]; // delete after obtaining address
        delete _addressToWeight[_newAddress]; // delete after recording weightedRandomKey
        emit Fullfilled(_newAddress, randomSeed, _weightedRandomKey);
    }

    /// @notice Add waitlist user into reservior.
    /// @dev Independent function to bear highest gas limit and avoid unnecessary on-chain call. 
    /// A-Res result not impacted by calculation sequency.
    /// @param waitlistAddress The address in waitlist to be added into reservior.
    function updateReservior(address waitlistAddress) external {
        if (winners[addressToIndex[waitlistAddress]] == waitlistAddress) revert AlreadyInReservior(); // check the existance of address in the array of winners
        if (addressToKey[waitlistAddress] == 0) revert NotListed(); // check whether in the waitlist

        // Prioritize filling unfilled reservoirs
        if (winners.length < winnersNumber) {
            _fillReservior(waitlistAddress);
        } else if (addressToKey[waitlistAddress] < maxWeightedRandomKey) { // check whether need to replace the user in the reservoir with waitlist user
            // Remove replaced address's index, leave it in waitlist
            delete addressToIndex[winners[lowestWinnerIndex]];  

            // Replace lowest ranked winner in reservoir with waitlist user
            addressToIndex[waitlistAddress] = lowestWinnerIndex;           
            winners[lowestWinnerIndex] = waitlistAddress;

            _updateReservior(); // update maxWeightedRandomKey with lowestWinnerIndex in the reservior
            emit Updated(waitlistAddress, addressToIndex[waitlistAddress]);
        }
    }

    /// @notice Any one can call this function to exit raffle irreversibly
    function exitRaffle() external {
        if (addressToKey[_msgSender()] == 0) revert NotListed();

        // Exit from reservior if existing
        if (winners[addressToIndex[_msgSender()]] == _msgSender()) {
            uint256 tailIndex = winners.length - 1;

            // Reorder when there is more than one user in the reservior.
            if (winners.length > 1) {
                // Replace the exited address with the last one in array and pop out it afterwards
                // unless the exited address is the last one in array
                if (addressToIndex[_msgSender()] < tailIndex) {
                    addressToIndex[winners[tailIndex]] = addressToIndex[_msgSender()];
                    winners[addressToIndex[_msgSender()]] = winners[tailIndex];
                }
            }

            winners.pop(); // pop out the tailIndex
            
            if (addressToIndex[_msgSender()] == lowestWinnerIndex)
                _updateReservior(); // update reservior if lowestWinnerIndex exited

            delete addressToIndex[_msgSender()]; // delete the reservior index of exited address
        }

        delete addressToKey[_msgSender()]; // exit waitlist
        _addressToWeight[_msgSender()] = 1; // mark as requested
        emit ExitRaffle(_msgSender(), winners.length);
    }

    /// @notice Admin can change number of winners before the start of raffle.
    /// @param number The new number of winners.
    function setWinnersNumber(uint256 number) external onlyOwner {
        if (block.timestamp >= startTime) revert AlreadyStart();
        if (number == 0) revert NoWinner();

        winnersNumber = number;
    }

    function setTime(uint256 startTime_, uint256 endTime_) external onlyOwner {
        if (block.timestamp >= startTime || block.timestamp >= startTime_) revert AlreadyStart();
        if (startTime >= endTime_) revert IncorrectTime();

        startTime = startTime_;
        endTime = endTime_;
    }

    /// @notice Update the endTime to ethier extend the raffle or end it earlier.
    function setEndTime(uint256 endTime_) external onlyOwner {
        if (block.timestamp >= endTime) revert AlreadyEnd();
        if (startTime >= endTime_ || block.timestamp >= endTime_) revert IncorrectTime();

        endTime = endTime_;
    }

    function setSigner(address signer_) external onlyOwner {
        signer = signer_;
    }

    function isRaffleTime() public view returns (bool) {
        return block.timestamp >= startTime && block.timestamp <= endTime;
    }

    function verifySignature(
        string calldata _salt,
        address _userAddress,
        uint256 weight,
        bytes memory signature
    ) public view returns (bool) {
        bytes32 rawMessageHash = _getMessageHash(_salt, _userAddress, weight);

        return _recover(rawMessageHash, signature) == signer;
    }

    /// @dev Add new address into unfilled reservior
    function _fillReservior(address newAddress_) internal {
        if (newAddress_ == address(0)) revert ZeroAddress();

        //add new user into reservior
        winners.push(newAddress_);
        addressToIndex[newAddress_] = winners.length - 1;

        //update maxWeightedRandomKey with lowestWinnerIndex in the reservior
        if (addressToKey[newAddress_] > maxWeightedRandomKey) {
            maxWeightedRandomKey = addressToKey[newAddress_];
            lowestWinnerIndex = winners.length - 1;
        }

        emit FillReservior(
            newAddress_,
            addressToKey[newAddress_],
            winners.length,
            winners[lowestWinnerIndex],
            maxWeightedRandomKey,
            lowestWinnerIndex
        );
    }

    /// @dev update maxWeightedRandomKey with lowestWinnerIndex in the reservior
    function _updateReservior() internal {
        if (winners.length == 0) return;

        // winners[0] as default lowest ranked winner
        uint256 _lowestWinnerIndex = 0; 
        uint256 _weightedRandomKey = addressToKey[winners[0]];

        for (uint256 i = 1; i < winners.length; i++) {
            if (addressToKey[winners[i]] > _weightedRandomKey) {
                _weightedRandomKey = addressToKey[winners[i]];
                _lowestWinnerIndex = i;
            }
        }

        maxWeightedRandomKey = _weightedRandomKey;
        lowestWinnerIndex = _lowestWinnerIndex;

        emit UpdateReservior(winners[_lowestWinnerIndex], _weightedRandomKey, _lowestWinnerIndex);
    }

    function _getMessageHash(
        string calldata _salt,
        address _userAddress,
        uint256 weight
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(_salt, address(this), _userAddress, weight));
    }

    function _recover(bytes32 _rawMessageHash, bytes memory signature) internal pure returns (address) {
        return _rawMessageHash.toEthSignedMessageHash().recover(signature);
    }
}
