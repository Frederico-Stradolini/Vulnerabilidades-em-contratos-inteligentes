// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ContratoVulneravel {
    mapping(address => uint256) public saldo;

    function depositar() public payable {
        saldo[msg.sender] += msg.value;
    }

    function sacar(uint256 _amount) public {
        require(saldo[msg.sender] >= _amount, "Saldo insuficiente");
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transferencia falhou");
        saldo[msg.sender] -= _amount;
    }
}