// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IPriceOracle {
    struct Price {
        uint256 base;
        uint256 premium;
    }
    function price(string calldata name, uint256 expires, uint256 duration) external view returns (Price calldata);
    function priceAsUSD(string calldata name, uint256 expires, uint256 duration) external view returns (Price calldata);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface AggregatorV3Interface {
    function latestAnswer() external view returns (int256);
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

error InsufficientValue(uint);

contract DeamEtherVaults {
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	address public owner;
	address public controller;
	address public immutable prices;
	address public immutable usdt;
	uint8 public immutable usdtDecimals;

	event ChangedController(address _old, address _new);
	event RegisterDomain(address _owner, string _label, uint _duration, uint _amount, bool _asUsd);
	event RenewDomain(string[] _labels, uint _duration, uint _amount, bool _asUsd);

	constructor(address _controller, address _prices, address _usdt, uint8 _usdtDecimals) {
		owner = msg.sender;
		controller = _controller;
		usdt = _usdt;
		prices = _prices;
		usdtDecimals = _usdtDecimals;
	}
	
	function transferOwnership(address _owner) public onlyOwner {
		emit OwnershipTransferred(owner, _owner);
		owner = _owner;
	}

	modifier onlyOwner() {
		require(owner==msg.sender, "DeamVaults: should be owner");
		_;
	}
	
	modifier onlyController () {
		require(controller==msg.sender || owner==msg.sender, "DeamVaults: should be controller");
		_;
	}

	receive() external payable {}
	fallback() external payable {}

	function setController(address _controller) external onlyOwner {
		require(_controller!=address(0), "DeamVaults: should be non zero");
		emit ChangedController(controller, _controller);
		controller = _controller;
	}
	
	function getPrice(string memory _label, uint _duration, bool _asUsd) public view returns (uint _price) {
		if (_asUsd) {
			IPriceOracle.Price memory price = IPriceOracle(prices).priceAsUSD(_label, 0, _duration);
			_price = (price.base + price.premium) / (10 ** (18 - usdtDecimals));
		} else {
			IPriceOracle.Price memory price = IPriceOracle(prices).price(_label, 0, _duration);
			_price = price.base + price.premium;
		}
	}

	function getExtendedPrices(string[] memory _labels, uint _duration, bool _asUsd) public view returns (uint _price) {
		for (uint _i = 0; _i < _labels.length; _i++) {
			_price += getPrice(_labels[_i], _duration, _asUsd);
		}
	}

	function registerDomain(string memory _label, uint _duration) public payable {
		bool _asUsd = msg.value==0;
		uint _price = getPrice(_label, _duration, _asUsd);
		if (_asUsd) {
			TransferHelper.safeTransferFrom(usdt, msg.sender, address(this), _price);
		} else {
			if (msg.value < _price) revert InsufficientValue(_price);
			if (msg.value - _price > 1e14) {
				(bool _result,) = msg.sender.call{value: msg.value - _price}("");
				require(_result, "refund ethers");
			}
		}
		emit RegisterDomain(msg.sender, _label, _duration, _price, _asUsd);
	}

	function renewDomain(string[] memory _labels, uint _duration) public payable {
		bool _asUsd = msg.value==0;
		uint _price = getExtendedPrices(_labels, _duration, _asUsd);
		if (_asUsd) {
			TransferHelper.safeTransferFrom(usdt, msg.sender, address(this), _price);
		} else {
			if (msg.value < _price) revert InsufficientValue(_price);
			if (msg.value - _price > 1e14) {
				(bool _result,) = msg.sender.call{value: msg.value - _price}("");
				require(_result, "refund ethers");
			}
		}
		emit RenewDomain(_labels, _duration, _price, _asUsd);
	}

	function withdraw(address _token, address to) public onlyController {
		require(to!=address(0), "DeamVaults: should be non zero");		
		if (_token==address(0)) {
			(bool _result,) = to.call{value: address(this).balance}("");
			require(_result, "refund ethers");
		} else {
			TransferHelper.safeTransfer(_token, to, IERC20(_token).balanceOf(address(this)));
		}
	}
}