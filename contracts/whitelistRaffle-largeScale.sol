// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./utils/VRFConsumerBaseV2Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@prb/math/contracts/PRBMathSD59x18.sol";
import "@prb/math/contracts/PRBMathUD60x18.sol";

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

contract WeightedRaffle is VRFConsumerBaseV2Upgradeable, OwnableUpgradeable {
    using PRBMathSD59x18 for int256;
    // using PRBMathUD60x18 for uint256;
    using ECDSAUpgradeable for bytes32;

    VRFCoordinatorV2Interface public constant VRF_COORDINATOR =
        VRFCoordinatorV2Interface(0x7a1BaC17Ccc5b313516C5E16fb24f7659aA5ebed);
    bytes32 public constant KEY_HASH = 0x4b09e658ed251bcafeebbc69400383d49f344ace09b9576fe248bb02c003fe9f; //matic testnet

    uint256 public reserviorHeight; //当前所有中奖者数量，也是当前蓄水池高度，不会超过winnersLength
    uint256 public lowestWinnerIndex; //lowest ranked winner in reservoir, 0 ~ winnerSize-1, 当前所有中奖者数量，weightedRandomKey最大的，获奖概率最低的
    uint256 public maxWeightedRandomKey; //worst weightedRandomKey, 最小获奖概率, 蓄水池当前最大的加权随机值

    //合约初始化时入参赋值
    uint256 public startTime;
    uint256 public endTime;
    uint256 public winnersLength; //also the size of reservoir, 也是蓄水池的最高高度，初始化是必须大于0
    address public signer;
    struct RequestConfig {
        bytes32 keyHash;
        uint64 subId;
        uint32 callbackGasLimit;
        uint16 requestConfirmations;
        uint32 numWords;
    }
    RequestConfig public s_requestConfig;

    mapping(uint256 => address) private _requestIdToAddress; //对应随机数与用户地址
    mapping(address => uint256) private _addressToWeight; //对应用户地址与其权重
    mapping(address => uint256) public addressToKey; //对应用户地址与其weightedRandomKey, waitlist用户使用
    mapping(address => uint256) public addressToIndex; //对应用户地址与其在winners数据中的位置，1 ~ winnersLength

    address[] public winners; //the reservior, 存储蓄水池中winner地址列表

    //对任何涉及可能改变蓄水池参数的事件，都暴露出当前蓄水池最新的参数
    event Requested(address indexed newAddress, uint256 weight, uint256 requestID);
    event FillReservior(
        address indexed newAddress,
        uint256 addressToKey,
        uint256 reserviorHeight,
        address indexed lowestWinnerAddress,
        uint256 maxWeightedRandomKey,
        uint256 lowestWinnerIndex
    );
    event Fullfilled(address indexed newAddress, int256 randomSeed, uint256 weightedRandomKey, bool listed);
    event UpdateReservior(address indexed lowestWinnerAddress, uint256 lowestWinnerIndex, uint256 maxWeightedRandomKey);
    event Updated(address indexed waitlistAddress, uint256 addressToIndex);
    event ExitRaffle(address indexed listedAddress, uint256 reserviorHeight);
    event IncreaseWinnersLength(uint256 winnersLength);
    event DecreaseWinnersLength(uint256 winnersLength);

    function initialize(
        uint256 startTime_,
        uint256 endTime_,
        uint256 winnersLength_,
        address signer_,
        uint64 subId_
    ) public initializer {
        __Ownable_init_unchained();
        __VRFConsumerBaseV2_init(address(VRF_COORDINATOR));

        startTime = startTime_;
        endTime = endTime_;
        winnersLength = winnersLength_;
        signer = signer_;

        s_requestConfig = RequestConfig(
            KEY_HASH,
            subId_,
            100000, //callbackGasLimit
            3, //requestConfirmations
            1 //numWords,
        );
    }

    //***需要改为metx tx***
    function requestRandomWords(
        uint256 weight,
        string calldata salt,
        bytes calldata signature
    ) external {
        if (!isRaffleTime()) revert NotRaffleTime();
        //weight must be greator than 0
        if (weight == 0) revert WeightIsZero();
        //每个地址只能抽奖一次，addressToWeight或addressToKey初始化过就不可以再参加
        if (_addressToWeight[msg.sender] != 0 || addressToKey[msg.sender] != 0) revert RepeatedRequest(); //改成metx tx后，msg.sender改成签名的用户
        //校验签名是否正确，确保weight是可信来源
        if (!verifySignature(salt, msg.sender, weight, signature)) revert InvalidSignature();

        RequestConfig memory rc = s_requestConfig;
        uint256 requestId = VRF_COORDINATOR.requestRandomWords(
            rc.keyHash,
            rc.subId,
            rc.requestConfirmations,
            rc.callbackGasLimit,
            rc.numWords
        );

        //用以区分不同用户请求的随机数及其抽奖weight Return the requestId to the requester.
        _requestIdToAddress[requestId] = msg.sender;
        _addressToWeight[msg.sender] = weight;

        emit Requested(msg.sender, weight, requestId);
    }

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
        //weighted random sampling, solidity adjusted A-RES algorithm, weightedRandomKey
        address _newAddress = _requestIdToAddress[requestId]; //这个局域变量是不是多余了，会浪费gas？
        delete _requestIdToAddress[requestId]; //取得地址后不需要保留和requestID的关系

        //ensure weightedRandomKey not be infinity through ranging randomSeed of 1 ~ 999,999
        int256 randomSeed = int256(randomWords[0] % 1000000);

        uint256 _weightedRandomKey;

        // uint256 _weightedRandomKey = (
        //     randomSeed == 0
        //         ? type(uint256).max //log2(0) = infinity
        //         : uint256(((1e18 * (randomSeed / 1000000).log2()) / int256(_addressToWeight[_newAddress])).abs())
        // );

        if (randomSeed == 0) {
            _weightedRandomKey = type(uint256).max;
        } else {
            _weightedRandomKey = uint256(
                ((1e18 * (randomSeed / 1000000).log2()) / int256(_addressToWeight[_newAddress])).abs()
            );
        }

        //_weightedRandomKey must be greater than 0 to identity the address being waitlisted
        //prevent edge case of _weightedRandomKey==0 when calculation result exceeding precision
        if (_weightedRandomKey == 0) {
            unchecked {
                _weightedRandomKey = _weightedRandomKey + 1;
            }
        }

        addressToKey[_newAddress] = _weightedRandomKey; //地址mapping到key，进入waitlist，以便后续比对更新蓄水池
        delete _addressToWeight[_newAddress]; //已记录key，可以删除weight节省gas

        //优先填充未满的蓄水池
        if (reserviorHeight < winnersLength) _fillReservior(_newAddress); //更新蓄水池中的地址及各参数

        emit Fullfilled(_newAddress, randomSeed, _weightedRandomKey, addressToKey[_newAddress] == 0 ? false : true); //最后一项为0代表落选，为1代表在蓄水池或候选名单
    }

    //为了不受chainlink回调的gaslimit约束以及尽量减少高并发时不必要的链上状态改变，且A-Res算法采样的结果与顺序无关，故使用单独的更新蓄水池方法。
    function updateReservior(address waitlistAddress) external {
        if (addressToIndex[waitlistAddress] != 0) revert AlreadyInReservior(); //校验是否addressToIndex有赋值，保证蓄水池中的地址不重复
        if (addressToKey[waitlistAddress] == 0) revert NotListed(); //校验是否addressToKey有赋值，以确定是否在waitlist

        //优先填充未满的蓄水池
        if (reserviorHeight < winnersLength) {
            _fillReservior(waitlistAddress);
        }
        //check whether need to replace the user in the reservoir with waitlist user
        else if (addressToKey[waitlistAddress] < maxWeightedRandomKey) {
            //replace lowest ranked winner in reservoir with waitlist user
            addressToIndex[waitlistAddress] = addressToIndex[winners[lowestWinnerIndex]]; //复制被代替者的Index
            delete addressToIndex[winners[lowestWinnerIndex]]; //删除被代替者的Index，踢入waitlist

            winners[lowestWinnerIndex] = waitlistAddress; //数组中老账户替换为新账户

            _updateReservior(); //update maxWeightedRandomKey with lowestWinnerIndex in the reservior 更新lowestWinner数据
        }

        emit Updated(waitlistAddress, addressToIndex[waitlistAddress]); //最后一项为0代表未进蓄水池，非0代表进了蓄水池
    }

    //***需要改为metx tx*** 某些用户希望退出抽奖，先退出蓄水池，再退出waitlist
    function exitRaffle() external {
        if (addressToKey[msg.sender] == 0) revert NotListed();

        //优先从蓄水池退出
        if (addressToIndex[msg.sender] > 0) {
            //改成metx tx后，msg.sender改成签名的用户
            uint256 _index = addressToIndex[msg.sender] - 1;

            reserviorHeight--;

            //蓄水中还有超过一个用户时需要重新排序
            if (reserviorHeight > 1) {
                //将数组最后一位补充上来，除非退出者刚好是最后一位
                if (_index < reserviorHeight) {
                    winners[_index] = winners[reserviorHeight];
                    addressToIndex[winners[_index]] = addressToIndex[msg.sender];
                }

                if (lowestWinnerIndex == _index) _updateReservior(); //如果删除的刚好是lowestWinner，要再更新一遍蓄水池最差值
            }

            delete winners[reserviorHeight];
            delete addressToIndex[msg.sender]; //exit reservior 删除退出者的Index，退出蓄水池
        }

        delete addressToKey[msg.sender]; //exit waitlist 删除退出者的weightedRandomKey，之后不能再加入waitlist
        _addressToWeight[msg.sender] = 1; //mark exited address as randomWord requested

        emit ExitRaffle(msg.sender, reserviorHeight);
    }

    //update maxWeightedRandomKey with lowestWinnerIndex in the reservior
    function _updateReservior() internal {
        uint256 _lowestWinnerIndex;
        uint256 _weightedRandomKey = addressToKey[winners[_lowestWinnerIndex]];

        for (uint256 i = 1; i < reserviorHeight; i++) {
            if (addressToKey[winners[i]] > _weightedRandomKey) {
                _weightedRandomKey = addressToKey[winners[i]];
                _lowestWinnerIndex = i;
            }
        }

        maxWeightedRandomKey = _weightedRandomKey;
        lowestWinnerIndex = _lowestWinnerIndex;

        emit UpdateReservior(winners[lowestWinnerIndex], maxWeightedRandomKey, lowestWinnerIndex);
    }

    function _fillReservior(address newAddress_) internal {
        //add new user into reservior
        winners[reserviorHeight] = newAddress_;

        //update maxWeightedRandomKey with lowestWinnerIndex in the reservior
        if (addressToKey[newAddress_] > maxWeightedRandomKey) {
            maxWeightedRandomKey = addressToKey[newAddress_];
            lowestWinnerIndex = reserviorHeight;
        }

        reserviorHeight++; //update the height of reservoir
        addressToIndex[newAddress_] = reserviorHeight; //记录用户在winners数组中的位置，1 ~ winnersLength

        emit FillReservior(
            newAddress_,
            addressToKey[newAddress_],
            reserviorHeight,
            winners[lowestWinnerIndex],
            maxWeightedRandomKey,
            lowestWinnerIndex
        );
    }

    function setWinnersLength(uint256 length) external onlyOwner {
        if (block.timestamp >= startTime) revert AlreadyStart();
        if (length == 0) revert NoWinner();

        winnersLength = length;
    }

    function setTime(uint256 startTime_, uint256 endTime_) external onlyOwner {
        if (block.timestamp >= startTime || block.timestamp >= startTime_) revert AlreadyStart();
        if (startTime >= endTime_) revert IncorrectTime();

        startTime = startTime_;
        endTime = endTime_;
    }

    /**
    @notice update the endTime to ethier extend the raffle or end it early.
     */
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
