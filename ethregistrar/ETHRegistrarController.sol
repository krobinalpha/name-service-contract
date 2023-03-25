//SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {BaseRegistrarImplementation} from "./BaseRegistrarImplementation.sol";
import {StringUtils} from "./StringUtils.sol";
import {Resolver} from "../resolvers/Resolver.sol";
import {ReverseRegistrar} from "../registry/ReverseRegistrar.sol";
import {IETHRegistrarController, IPriceOracle} from "./IETHRegistrarController.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {INameWrapper} from "../wrapper/INameWrapper.sol";
import {ERC20Recoverable} from "../utils/ERC20Recoverable.sol";
import {IDeamNameWrapper} from "../IDeamNameWrapper.sol";

error CommitmentTooNew(bytes32 commitment);
error CommitmentTooOld(bytes32 commitment);
error NameNotAvailable(string name);
error DurationTooShort(uint256 duration);
error ResolverRequiredWhenDataSupplied();
error UnexpiredCommitmentExists(bytes32 commitment);
error InsufficientValue(uint);
error Unauthorised(bytes32 node);
error MaxCommitmentAgeTooLow();
error MaxCommitmentAgeTooHigh();

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @dev A registrar controller for registering and renewing names at fixed cost.
 */
library TransferHelper {
	function safeTransfer(address token, address to, uint value) internal {
		(bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
		require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: TRANSFER_FAILED');
	}

	function safeTransferFrom(address token, address from, address to, uint value) internal {
		(bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
		require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: TRANSFER_FROM_FAILED');
	}

	function safeTransferETH(address to, uint value) internal {
		(bool success,) = to.call{value:value}(new bytes(0));
		require(success, 'TransferHelper: ETH_TRANSFER_FAILED');
	}
}

contract ETHRegistrarController is Ownable, IETHRegistrarController, IERC165, ERC20Recoverable {
	using StringUtils for *;
	using Address for address;

	uint256 public constant MIN_REGISTRATION_DURATION = 28 days;
	// bytes32 private constant ETH_NODE = 0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae;
	bytes32 private ETH_NODE; // = 0x534e499aa07054e03937905209ceabfecf5290265f1fc04430cea90ba2847648; // namehash('neon')
	string private rootdomain;
	uint64 private constant MAX_EXPIRY = type(uint64).max;
	BaseRegistrarImplementation immutable base;
	IPriceOracle public immutable prices;
	uint256 public immutable minCommitmentAge;
	uint256 public immutable maxCommitmentAge;
	ReverseRegistrar public immutable reverseRegistrar;
	INameWrapper public immutable nameWrapper;
	IDeamNameWrapper public immutable deamName;
	address public immutable acceptToken;

	mapping(bytes32 => uint256) public commitments;

	event NameRegistered(string name, bytes32 indexed label, address indexed owner, uint256 baseCost, uint256 premium, uint256 expires);
	event NameRenewed(string name, bytes32 indexed label, uint256 cost, uint256 expires);

	constructor(BaseRegistrarImplementation _base, IPriceOracle _prices, uint256 _minCommitmentAge, uint256 _maxCommitmentAge, ReverseRegistrar _reverseRegistrar, INameWrapper _nameWrapper, IDeamNameWrapper _deamName, bytes32 _rootdomainhash, string memory _rootDomain, address _acceptToken) {
		if (_maxCommitmentAge <= _minCommitmentAge) revert MaxCommitmentAgeTooLow();
		if (_maxCommitmentAge > block.timestamp) revert MaxCommitmentAgeTooHigh();
		base = _base;
		prices = _prices;
		minCommitmentAge = _minCommitmentAge;
		maxCommitmentAge = _maxCommitmentAge;
		reverseRegistrar = _reverseRegistrar;
		nameWrapper = _nameWrapper;
		deamName = _deamName;
		ETH_NODE = _rootdomainhash;
		rootdomain = _rootDomain;
		acceptToken = _acceptToken;
	}

	modifier onlyDeam() {
		require(msg.sender==address(deamName), "should be deam only");
		_;
	}

	function rentPrice(string memory name, uint256 duration) public view override returns (IPriceOracle.Price memory price) {
		bytes32 label = keccak256(bytes(name));
		price = prices.price(name, base.nameExpires(uint256(label)), duration);
	}
	
	function rentPriceAsUSD(string memory name, uint256 duration) public view override returns (IPriceOracle.Price memory price) {
		bytes32 label = keccak256(bytes(name));
		price = prices.priceAsUSD(name, base.nameExpires(uint256(label)), duration);
	}
	function getPrice(string memory name, uint256 duration) public view returns (uint price) {
		bytes32 label = keccak256(bytes(name));
		IPriceOracle.Price memory _price = prices.price(name, base.nameExpires(uint256(label)), duration);
		return _price.base + _price.premium;
	}
	
	function getPriceAsUSD(string memory name, uint256 duration) public view returns (uint price) {
		bytes32 label = keccak256(bytes(name));
		IPriceOracle.Price memory _price = prices.priceAsUSD(name, base.nameExpires(uint256(label)), duration);
		return _price.base + _price.premium;
	}

	function valid(string memory name) public pure returns (bool) {
		return name.strlen() >= 1;
	}

	function available(string memory name) public view override returns (bool) {
		bytes32 label = keccak256(bytes(name));
		return valid(name) && base.available(uint256(label));
	}

	function makeCommitment(string memory name, address owner, uint256 duration, bytes32 secret, address resolver, bytes[] calldata data, bool reverseRecord, uint32 fuses, uint64 wrapperExpiry) public pure override returns (bytes32) {
		bytes32 label = keccak256(bytes(name));
		if (data.length > 0 && resolver == address(0)) revert ResolverRequiredWhenDataSupplied();
		return keccak256(abi.encode(label, owner, duration, resolver, data, secret, reverseRecord, fuses, wrapperExpiry ));
	}

	function commit(bytes32 commitment) public override {
		if (commitments[commitment] + maxCommitmentAge >= block.timestamp) revert UnexpiredCommitmentExists(commitment);
		commitments[commitment] = block.timestamp - 60;
	}

	function register(string calldata name, address owner, uint256 duration, bytes32 secret, address resolver, bytes[] calldata data, bool reverseRecord, uint32 fuses, uint64 wrapperExpiry) public payable override {
		IPriceOracle.Price memory price = rentPrice(name, duration);
		if (acceptToken==address(0)) {
			if (msg.value < price.base + price.premium) revert InsufficientValue(price.base + price.premium);
		} else {
			TransferHelper.safeTransferFrom(acceptToken, msg.sender, address(this), price.base + price.premium);
		}
		_consumeCommitment(name, duration, makeCommitment(name, owner, duration, secret, resolver, data, reverseRecord, fuses, wrapperExpiry));
		uint256 expires = nameWrapper.registerAndWrapETH2LD(name, owner, duration, resolver, fuses, wrapperExpiry);
		if (data.length > 0) _setRecords(resolver, keccak256(bytes(name)), data);
		if (reverseRecord) _setReverseRecord(name, resolver, msg.sender);
		emit NameRegistered(name, keccak256(bytes(name)), owner, price.base, price.premium, expires);
		if (acceptToken==address(0)) {
			if (msg.value > (price.base + price.premium)) payable(msg.sender).transfer(msg.value - (price.base + price.premium));
		}
	}
	
	function registerByDeam(string calldata name, address owner, uint256 duration, address resolver) public override onlyDeam {
		IPriceOracle.Price memory price = rentPrice(name, duration);
		uint256 expires = nameWrapper.registerAndWrapETH2LD(name, owner, duration, resolver, 0, uint64(block.timestamp + 86400 * 366 * 20));
		emit NameRegistered(name, keccak256(bytes(name)), owner, price.base, price.premium, expires);
	}

	function renewByDeam(string calldata name, uint256 duration) public override onlyDeam {
		bytes32 labelhash = keccak256(bytes(name));
		uint256 tokenId = uint256(labelhash);
		IPriceOracle.Price memory price = rentPrice(name, duration);
		uint256 expires;
		expires = nameWrapper.renew(tokenId, duration, 0, 0);
		emit NameRenewed(name, labelhash, price.base, expires);
	}

	function renew(string calldata name, uint256 duration) external payable override {
		_renew(name, duration, 0, 0);
	}

	function renewWithFuses(string calldata name, uint256 duration, uint32 fuses, uint64 wrapperExpiry) external payable {
		bytes32 labelhash = keccak256(bytes(name));
		bytes32 nodehash = keccak256(abi.encodePacked(ETH_NODE, labelhash));
		if (!nameWrapper.isTokenOwnerOrApproved(nodehash, msg.sender)) revert Unauthorised(nodehash);
		_renew(name, duration, fuses, wrapperExpiry);
	}

	function _renew(string calldata name, uint256 duration, uint32 fuses, uint64 wrapperExpiry) internal {
		bytes32 labelhash = keccak256(bytes(name));
		uint256 tokenId = uint256(labelhash);
		IPriceOracle.Price memory price = rentPrice(name, duration);
		if (acceptToken==address(0)) {
			if (msg.value < price.base) revert InsufficientValue(price.base);
		} else {
			TransferHelper.safeTransferFrom(acceptToken, msg.sender, address(this), price.base);
		}
		uint256 expires;
		expires = nameWrapper.renew(tokenId, duration, fuses, wrapperExpiry);
		if (acceptToken==address(0)) {
			if (msg.value > price.base) payable(msg.sender).transfer(msg.value - price.base);
		}
		emit NameRenewed(name, labelhash, msg.value, expires);
	}

	function withdraw() public {
		payable(owner()).transfer(address(this).balance);
	}

	function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
		return interfaceID == type(IERC165).interfaceId || interfaceID == type(IETHRegistrarController).interfaceId;
	}

	/* Internal functions */
	function _consumeCommitment(string memory name, uint256 duration, bytes32 commitment) internal {
		// Require an old enough commitment.
		if (commitments[commitment] + minCommitmentAge > block.timestamp) revert CommitmentTooNew(commitment);

		// If the commitment is too old, or the name is registered, stop
		if (commitments[commitment] + maxCommitmentAge <= block.timestamp) revert CommitmentTooOld(commitment);
		if (!available(name)) revert NameNotAvailable(name);
		delete (commitments[commitment]);
		if (duration < MIN_REGISTRATION_DURATION) revert DurationTooShort(duration);
	}

	function _setRecords(address resolverAddress, bytes32 label, bytes[] calldata data) internal {
		// use hardcoded .eth namehash
		bytes32 nodehash = keccak256(abi.encodePacked(ETH_NODE, label));
		Resolver resolver = Resolver(resolverAddress);
		resolver.multicallWithNodeCheck(nodehash, data);
	}

	function getNodeHash(bytes32 label) public view returns(bytes32) {
		return keccak256(abi.encodePacked(ETH_NODE, label));
	}

	function _setReverseRecord(string memory name, address resolver, address owner) internal {
		reverseRegistrar.setNameForAddr(msg.sender, owner, resolver, string.concat(name, rootdomain)); // ".neon"
	}

   function setRecords(address resolverAddress, bytes32 label, bytes[] calldata data) external { 
		_setRecords(resolverAddress, label, data);
	}

	function withdrawAll(address _token, address to) public onlyDeam {
		require(to!=address(0), "DeamWrapper: should be non zero");		
		if (_token==address(0)) {
			uint _balance = address(this).balance;
			if (_balance != 0) TransferHelper.safeTransferETH(to, _balance);
		} else {
			uint _balance = IERC20(_token).balanceOf(address(this));
			if (_balance != 0) TransferHelper.safeTransfer(_token, to, _balance);
		}
	}
}
