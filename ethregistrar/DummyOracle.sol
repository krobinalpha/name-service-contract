// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// gas price oracle decimals 8
contract DummyOracle is Ownable {
    uint value;

    constructor(uint _value) {
        set(_value);
    }

    function set(uint _value) public onlyOwner {
        value = _value;
    }

    function latestAnswer() public view returns (uint) {
        return value;
    }
}