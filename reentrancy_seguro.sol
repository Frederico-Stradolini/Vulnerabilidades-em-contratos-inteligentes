// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ContratoVulneravel {
    bool private locked;
    mapping(address => uint256) public saldo;

    modifier noReentrancy() {
        require(!locked, "Sem reentrancia permitida");
        locked = true;
        _;
        locked = false;
    }

    function depositar() public payable {
        saldo[msg.sender] += msg.value;
    }

    function sacar(uint256 _amount) public noReentrancy{
        require(saldo[msg.sender] >= _amount, "Saldo insuficiente");
        saldo[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transferencia falhou");
    }
}