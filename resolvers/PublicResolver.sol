//SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../registry/ENS.sol";
import "./profiles/ABIResolver.sol";
import "./profiles/AddrResolver.sol";
import "./profiles/ContentHashResolver.sol";
import "./profiles/DNSResolver.sol";
import "./profiles/InterfaceResolver.sol";
import "./profiles/NameResolver.sol";
import "./profiles/PubkeyResolver.sol";
import "./profiles/TextResolver.sol";
import "./Multicallable.sol";

import {IDeamNameWrapper} from "../IDeamNameWrapper.sol";

interface INameWrapper {
	function ownerOf(uint256 id) external view returns (address);
}

/**
 * A simple resolver anyone can use; only allows the owner of a node to set its
 * address.
 */
contract PublicResolver is
	Multicallable,
	ABIResolver,
	AddrResolver,
	ContentHashResolver,
	DNSResolver,
	InterfaceResolver,
	NameResolver,
	PubkeyResolver,
	TextResolver
{
	ENS immutable ens;
	INameWrapper immutable nameWrapper;
	address immutable trustedETHController;
	address immutable trustedReverseRegistrar;

	IDeamNameWrapper deamname;
	
	/**
	 * A mapping of operators. An address that is authorised for an address
	 * may make any changes to the name that the owner could, but may not update
	 * the set of authorisations.
	 * (owner, operator) => approved
	 */
	mapping(address => mapping(address => bool)) private _operatorApprovals;

	// Logged when an operator is added or removed.
	event ApprovalForAll(
		address indexed owner,
		address indexed operator,
		bool approved
	);

	constructor(
		ENS _ens,
		INameWrapper wrapperAddress,
		address _trustedETHController,
		address _trustedReverseRegistrar,
		IDeamNameWrapper _deamname
	) {
		ens = _ens;
		nameWrapper = wrapperAddress;
		trustedETHController = _trustedETHController;
		trustedReverseRegistrar = _trustedReverseRegistrar;
		deamname = _deamname;
	}

	function setText(bytes32 node, string calldata key, string calldata value) public override {
		deamname.addTextKey(node, key);
		versionable_texts[recordVersions[node]][node][key] = value;
		emit TextChanged(node, key, key, value);
	}

	/**
	 * @dev See {IERC1155-setApprovalForAll}.
	 */
	function setApprovalForAll(address operator, bool approved) external {
		require(
			msg.sender != operator,
			"ERC1155: setting approval status for self"
		);

		_operatorApprovals[msg.sender][operator] = approved;
		emit ApprovalForAll(msg.sender, operator, approved);
	}

	/**
	 * @dev See {IERC1155-isApprovedForAll}.
	 */
	function isApprovedForAll(address account, address operator)
		public
		view
		returns (bool)
	{
		return _operatorApprovals[account][operator];
	}

	function isAuthorised(bytes32 node) internal view override returns (bool) {
		if (
			msg.sender == trustedETHController ||
			msg.sender == trustedReverseRegistrar
		) {
			return true;
		}
		address owner = ens.owner(node);
		if (owner == address(nameWrapper)) {
			owner = nameWrapper.ownerOf(uint256(node));
		}
		return owner == msg.sender || isApprovedForAll(owner, msg.sender);
	}

	function supportsInterface(bytes4 interfaceID)
		public
		view
		override(
			Multicallable,
			ABIResolver,
			AddrResolver,
			ContentHashResolver,
			DNSResolver,
			InterfaceResolver,
			NameResolver,
			PubkeyResolver,
			TextResolver
		)
		returns (bool)
	{
		return super.supportsInterface(interfaceID);
	}
}
