// SPDX-License-Identifier: MIT

pragma solidity  ^0.8.17; 

interface IDeamNameWrapper {
    function addDomain(address _account, string calldata _label) external;
    function addSubDomain(address _account, bytes32 _parentNode, string calldata _label) external;
    function deleteSubDomain(bytes32 _parentNode, string calldata _label) external;
    function addTextKey(bytes32 _nodehash, string calldata _key) external;
    function changeOwner(uint _node, address _owner) external;
}