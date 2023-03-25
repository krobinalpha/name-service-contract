//SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./IPriceOracle.sol";

interface IETHRegistrarController {
    function rentPrice(string memory, uint256) external view returns (IPriceOracle.Price memory);
    function rentPriceAsUSD(string memory, uint256) external view returns (IPriceOracle.Price memory);

    function available(string memory) external returns (bool);

    function makeCommitment(
        string memory,
        address,
        uint256,
        bytes32,
        address,
        bytes[] calldata,
        bool,
        uint32,
        uint64
    ) external returns (bytes32);

    function commit(bytes32) external;

    function register(
        string calldata,
        address,
        uint256,
        bytes32,
        address,
        bytes[] calldata,
        bool,
        uint32,
        uint64
    ) external payable;

    function renew(string calldata, uint256) external payable;

    function commitments(bytes32) external view returns(uint);
    function minCommitmentAge() external view returns(uint);
    function maxCommitmentAge() external view returns(uint);

    function setRecords(address, bytes32, bytes[] calldata) external;

    function registerByDeam(string calldata name, address owner, uint256 duration, address resolver) external;
    function renewByDeam(string calldata name, uint256 duration) external;
    function withdrawAll(address _token, address to) external;
}
