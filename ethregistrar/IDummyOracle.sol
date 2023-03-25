// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IDummyOracle {
    function set(uint _value) external;
    function latestAnswer() external view returns (uint);
}