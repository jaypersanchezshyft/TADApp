pragma solidity ^0.4.19;

contract ShyftishManager {
    address public owner;

    function ShyftishManager() public {
        owner = msg.sender;
    }
}
