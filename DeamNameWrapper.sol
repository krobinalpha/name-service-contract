//SPDX-License-Identifier: MIT

/*
 Created
 by <Leo Pawel>leopawel65@gmail.com
 at 12/12/2022
*/

pragma solidity ^0.8.17;

import {ENS} from "./registry/ENS.sol";
import {Resolver} from "./resolvers/Resolver.sol";
import {IBaseRegistrar} from "./ethregistrar/IBaseRegistrar.sol";
import {IETHRegistrarController} from "./ethregistrar/IETHRegistrarController.sol";
import {IPriceOracle} from "./ethregistrar/IPriceOracle.sol";
import {IDummyOracle} from "./ethregistrar/IDummyOracle.sol";
import {INameWrapper} from "./wrapper/INameWrapper.sol";


error MustbeOwner(string where, address sender);
error MustbeController(string where, address sender);
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}
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

contract DeamNameWrapper {
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	// uint public _changedOwner;
	// address public _currentOwner;
	// uint public _currentCount;

	address public owner;
    bytes32 private ETH_NODE; // = 0x534e499aa07054e03937905209ceabfecf5290265f1fc04430cea90ba2847648;

	mapping(uint=>string[]) _subdomains; 	// domainhash => subdomain names
	mapping(uint=>string[]) _recordKeys; 	// domainhash => text record keys

	mapping(uint=>string) _domains; 		// domainhash => domainname
	mapping(uint=>address) _registrants;	// initial owners for domain
    mapping(address=>string[]) _all;		// all registered domains by a account
    mapping(address=>uint[]) _owns;			// controllable domains by a account
	
	struct DomainInfo {
		string label;
		uint expires;
	}
	// struct RecordInfo {
	// 	string key;
	// 	string value;
	// }
	// struct Prices {
	// 	uint basePrice;
	// 	uint premiumPrice;
	// 	uint etherPrice;
	// }

	INameWrapper public nameWrapper;
	IETHRegistrarController public ethController;
	IDummyOracle public priceOracle;
	Resolver public resolver;
	address public controller;
	address public immutable acceptToken;

	constructor(bytes32 _rootHash, address _acceptToken) {
		owner = msg.sender;
		ETH_NODE = _rootHash;
		acceptToken = _acceptToken;
	}

    modifier onlyOwner() {
		if (msg.sender!=owner) revert MustbeOwner("deamname", msg.sender);
        _;
    }

	receive() external payable {}
	fallback() external payable {}

	function transferOwnership(address _owner) external onlyOwner {
		emit OwnershipTransferred(owner, _owner);
		owner = _owner;
	}

    modifier onlyController() {
        // require(msg.sender==address(nameWrapper) || msg.sender==address(resolver), MustbeController(msg.sender) ); // "deamname: must be controller"
		if (!isController(msg.sender)) revert MustbeController("deamname", msg.sender);
        _;
    }
	
	function isController(address _address) public view returns(bool) {
		return _address==owner || _address==controller || _address==address(nameWrapper) || _address==address(resolver);
	}

	function addController(INameWrapper _nameWrapper, IETHRegistrarController _ethController, IDummyOracle _priceOracle, Resolver _resolver, address _controller) public onlyOwner {
		nameWrapper = _nameWrapper;
		ethController = _ethController;
		priceOracle = _priceOracle;
		resolver = _resolver;
		controller = _controller;
	}
	// uint public flag;
	// Registers a new second-level domain
    function addDomain(address _account, string calldata _label) public onlyController {
		// flag += 1;
		uint _labelhash = uint256(keccak256(bytes(_label)));
		uint _nodehash = uint(keccak256(abi.encodePacked(ETH_NODE, _labelhash)));
		
		if (_registrants[_nodehash]==address(0)) {
			_registrants[_nodehash] = _account;
			_domains[_nodehash] = _label;
			_all[_account].push(_label);
		}
    }
    
	// Registers a new subdomain to second-level domain
	function addSubDomain(address _account, bytes32 _parentNode, string calldata _label) public onlyController {
		// flag += 10;
		uint __parentNode = uint(_parentNode);
		uint _labelhash = uint(keccak256(bytes(_label)));
		uint _nodehash = uint(keccak256(abi.encodePacked(_parentNode, _labelhash)));
		
		if (_registrants[_nodehash]==address(0)) {
			_registrants[_nodehash] = _account;
			_subdomains[__parentNode].push(_label);
			_domains[_nodehash] = string(abi.encodePacked(_label, ".", _domains[uint(_parentNode)]));
		}
		// for (uint k = 0; k < _owns[_account].length; k++) {
		// 	if (_owns[_account][k]==_nodehash) return;
		// }
		// _owns[_account].push(_nodehash);
    }

	
	
	function deleteSubDomain(bytes32 _parentNode, string calldata _label) public onlyController {
		// flag++;
		uint __parentNode = uint(_parentNode);
		uint _labelhash = uint(keccak256(bytes(_label)));
		uint _nodehash = uint(keccak256(abi.encodePacked(_parentNode, _labelhash)));
		if (_registrants[_nodehash]!=address(0)) {
			// flag++;
			address _owner = nameWrapper.ownerOf(_nodehash);
			delete _registrants[_nodehash];
			string[] storage _ss = _subdomains[__parentNode];
			for (uint k = 0; k < _ss.length; k++) {
				// flag++;
				uint _lhash = uint(keccak256(bytes(_ss[k])));
				if (_lhash==_labelhash) {
					// flag++;
					_ss[k] = _ss[_ss.length - 1];
					_ss.pop();
					break;
				}
			}
			delete _domains[_nodehash];
			// flag++;
			uint[] storage _ds = _owns[_owner];
			for (uint k = 0; k < _ds.length; k++) {
				// flag++;
				if (_ds[k]==_nodehash) {
					// flag++;
					_ds[k] = _ds[_ds.length - 1];
					_ds.pop();
					break;
				}
			}
		}
    }
	
	function addTextKey(bytes32 _nodehash, string calldata _key) public onlyController {
		uint _node = uint(_nodehash);
		for (uint k = 0; k < _recordKeys[_node].length; k++) {
			if (keccak256(abi.encodePacked(_recordKeys[_node][k])) == keccak256(abi.encodePacked(_key))) return;
		}
		_recordKeys[_node].push(_key);
    }
    
	// address[] public _cs;
	// function test() public view returns(address[] memory) {
	// 	return _cs;
	// }

	function changeOwner(uint _node, address _owner) public onlyController {
		// flag += 100;
		address _current = nameWrapper.ownerOf(_node);
		// _cs.push(_current);
		// _cs.push(_owner);
		if (_owner!=_current) {
			if (_current!=address(0)) {
				uint[] storage _t = _owns[_current];
				for (uint k = 0; k < _t.length; k++) {
					if (_t[k] == _node) {
						_t[k] = _t[_t.length - 1];
						_t.pop();
						break;
					}
				}
			}
			if (_owner!=address(0)) {
				for (uint k = 0; k < _owns[_owner].length; k++) {
					if (_owns[_owner][k]==_node) return;
				}
				_owns[_owner].push(_node);
			}
		}
    }

	function subdomains(uint _parentNode) public view returns(string[] memory) {
		return _subdomains[_parentNode];
	}

    function asRegistrant(address _account, uint _page, uint _pageCount) public view returns(uint _currentPage, uint _totalPage, DomainInfo[] memory _infos) {
		uint _count = _all[_account].length;
		if (_count!=0) {
			_totalPage = (_count - 1) / _pageCount + 1;
			if (_page > _totalPage) _page = _totalPage;
			if (_page < 1) _page = 1;
			uint _start = (_page - 1) * _pageCount;
			uint _last = _start + _pageCount;
			if (_last > _count) _last = _count;
			_currentPage = _page;
			_infos = new DomainInfo[](_last - _start);
			for (uint k = _start; k < _last; k++) {
				string memory _label = _all[_account][k];
				bytes32 _labelhash = keccak256(bytes(_label));
				IBaseRegistrar registrar = nameWrapper.registrar();
				uint _expire = registrar.nameExpires(uint(_labelhash));
				_infos[k] = DomainInfo(_label, _expire);
			}
		}
    }
    function asController(address _account, uint _page, uint _pageCount) public view returns(uint _currentPage, uint _totalPage, uint _count, DomainInfo[] memory _infos) {
		uint[] memory _ts = _owns[_account];
		DomainInfo[] memory _vs = new DomainInfo[](_ts.length);
		_count = 0;

		IBaseRegistrar _registrar = nameWrapper.registrar();
		for (uint k = 0; k < _ts.length; k++) {
			string memory _label = _domains[_ts[k]];
			bytes32 _labelhash = keccak256(bytes(_label));
			uint _expire = _registrar.nameExpires(uint(_labelhash));
			if (_expire==0 || _expire > block.timestamp) {
				_vs[_count++] = DomainInfo(_label, _expire);
			}
		}
		// uint _count = _owns[_account].length;
		if (_count!=0) {
			_totalPage = (_count - 1) / _pageCount + 1;
			if (_page > _totalPage) _page = _totalPage;
			if (_page < 1) _page = 1;
			uint _start = (_page - 1) * _pageCount;
			uint _last = _start + _pageCount;
			if (_last > _count) _last = _count;
			_currentPage = _page;
			_infos = new DomainInfo[](_last - _start);
			for (uint k = _start; k < _last; k++) {
				_infos[k - _start] = _vs[k];
			}
		}
    }

	// function byName(string memory _name) public view returns(
	// 	address _owner,
	// 	address _initialOwner,
	// 	uint _expire,
	// 	address _resolver,
	// 	bytes memory _contentHash,
	// 	string[] memory _texts,
	// 	Prices memory _prices
	// ) {
	// 	bytes32 _labelhash = keccak256(bytes(_name));
	// 	bytes32 _nodehash = keccak256(abi.encodePacked(ETH_NODE, _labelhash));

	// 	_owner = nameWrapper.ownerOf(uint(_nodehash));
	// 	_initialOwner = _registrants[uint(_nodehash)];
	// 	ENS registry = nameWrapper.ens();
	// 	IBaseRegistrar registrar = nameWrapper.registrar();
	// 	_resolver = registry.resolver(_nodehash);
	// 	_expire = registrar.nameExpires(uint(_labelhash));
	// 	_texts = new string[](13);
	// 	if (_resolver!=address(0)) {
	// 		Resolver __resolver = Resolver(_resolver);
	// 		_contentHash = __resolver.contenthash(_nodehash);
	// 		_texts[0] = __resolver.text(_nodehash, "snapshot");
	// 		_texts[1] = __resolver.text(_nodehash, "url");
	// 		_texts[2] = __resolver.text(_nodehash, "avatar");
	// 		_texts[3] = __resolver.text(_nodehash, "com.twitter");
	// 		_texts[4] = __resolver.text(_nodehash, "com.github");
	// 		_texts[5] = __resolver.text(_nodehash, "email");
	// 		_texts[6] = __resolver.text(_nodehash, "description");
	// 		_texts[7] = __resolver.text(_nodehash, "notice");
	// 		_texts[8] = __resolver.text(_nodehash, "keywords");
	// 		_texts[9] = __resolver.text(_nodehash, "com.discord");
	// 		_texts[10] = __resolver.text(_nodehash, "com.reddit");
	// 		_texts[11] = __resolver.text(_nodehash, "org.telegram");
	// 		_texts[12] = __resolver.text(_nodehash, "neon.delegate");
	// 	}
	// 	IPriceOracle.Price memory price = ethController.rentPrice(_name, 86400 * 366);
	// 	_prices.basePrice = price.base;
	// 	_prices.premiumPrice = price.premium;
	// 	_prices.etherPrice = priceOracle.latestAnswer();
	// }

	function getDomainInfo(string memory _label, bytes32 _nodehash, bool withPrice) public view returns(
		address[] memory _accounts, // [owner, initialOwner, resolver]
		// address _initialOwner,
		uint _expire,
		// address _resolver,
		bytes memory _contentHash,
		string[][] memory _texts,
		uint[] memory _prices,
		string[] memory _subs
	) {
		uint _labelhash = uint(keccak256(bytes(_label)));
		// bytes32 _labelhash = namehash.keccak256(_label);
		uint _ihash = uint(_nodehash);
		_accounts = new address[](3);
		_accounts[0] = nameWrapper.ownerOf(_ihash);
		if (_accounts[0]!=address(0)) {
			_accounts[1] = _registrants[_ihash];	
			ENS registry = nameWrapper.ens();
			IBaseRegistrar registrar = nameWrapper.registrar();
			_accounts[2] = registry.resolver(_nodehash);
			_expire = registrar.nameExpires(uint(_labelhash));
		}
		
		
		if (_accounts[2]!=address(0)) {
			Resolver __resolver = Resolver(_accounts[2]);
			_contentHash = __resolver.contenthash(_nodehash);
			string[] storage _keys = _recordKeys[_ihash];
			_texts = new string[][](_keys.length);
			for (uint k = 0; k < _keys.length; k++) {
				_texts[k] = new string[](2);
				_texts[k][0] = _keys[k];
				_texts[k][1] = __resolver.text(_nodehash, _keys[k]);
			}
		}

		if (withPrice) {
			_prices = new uint[](3);
			IPriceOracle.Price memory price = ethController.rentPrice(_label, 86400 * 366);
			_prices[0] = price.base;						// basePrice
			_prices[1] = price.premium;					// premiumPrice
			_prices[2] = priceOracle.latestAnswer();		// etherPrice		
		}
		{
			_subs = _subdomains[_ihash];
		}
	}

	function getLimitTime(bytes32 _commitmentHash) public view returns (
		uint _timestamp,
		uint _min,
		uint _max
	) {
		_timestamp = ethController.commitments(_commitmentHash);
		_min = ethController.minCommitmentAge();
		_max = ethController.maxCommitmentAge();
	}

	function getExtendedPrices (string[] memory _names, uint duration) public view returns (uint _basePrice, uint _premiumPrice, uint _etherPrice) {
		for (uint _i = 0;  _i < _names.length; _i++) {
			IPriceOracle.Price memory price = ethController.rentPrice(_names[_i], duration);
			_basePrice += price.base;
			_premiumPrice += price.premium;
		}
		_etherPrice = priceOracle.latestAnswer();
	}

	function getExpires(string[] memory _names) public view returns (uint[] memory _expires) {
		IBaseRegistrar registrar = nameWrapper.registrar();
		_expires = new uint[](_names.length);
		for (uint _i = 0;  _i < _names.length; _i++) {
			_expires[_i] = registrar.nameExpires(uint(keccak256(bytes(_names[_i]))));
		}
	}

	function renew(string[] memory _names, uint256 _duration) public payable {
		if (acceptToken==address(0)) {
			uint _value = msg.value;
			for (uint _i = 0; _i < _names.length; _i++) {
				IPriceOracle.Price memory price = ethController.rentPrice(_names[_i], _duration);
				ethController.renew{value: price.base + price.premium}(_names[_i], _duration);
				_value -= price.base + price.premium;
			}
			if (_value > 0) {
				(bool _result,) = msg.sender.call{value: _value}("");
				require(_result, "refund ethers");
			}
		} else {
			uint _value = 0;
			for (uint _i = 0; _i < _names.length; _i++) {
				IPriceOracle.Price memory price = ethController.rentPrice(_names[_i], _duration);
				ethController.renewByDeam(_names[_i], _duration);
				_value += price.base + price.premium;
			}
			TransferHelper.safeTransferFrom(acceptToken, msg.sender, address(this), _value);
		}
	}
	
	function registerByController(string calldata _name, address _owner, uint256 _duration, address _resolver) public onlyController {
		ethController.registerByDeam(_name, _owner, _duration, _resolver);
	}

	function renewByController(string[] memory _names, uint256 _duration) public onlyController {
		for (uint _i = 0; _i < _names.length; _i++) {
			ethController.renewByDeam(_names[_i], _duration);
		}
	}

    function withdraw(address _token, address to) public onlyController {
		require(to!=address(0), "DeamWrapper: should be non zero");		
		if (_token==address(0)) {
			ethController.withdrawAll(address(0), to);
			uint _balance = address(this).balance;
			if (_balance!=0) TransferHelper.safeTransferETH(to, _balance);
		} else {
			ethController.withdrawAll(_token, to);
			uint _balance = IERC20(_token).balanceOf(address(this));
			if (_balance!=0) TransferHelper.safeTransfer(_token, to, _balance);
		}
	}
}