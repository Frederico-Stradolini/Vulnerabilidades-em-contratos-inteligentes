// SPDX-License-Identifier: MIT

pragma solidity ^0.7.0; 
// Versão anterior a ^0.8.0, onde não há proteção automática contra overflow e underflow

contract ContratoNaoSeguro {
    uint8 public totalSupply;

    constructor() {
        totalSupply = 255;
    }

    function incrementarSupply() public {
        totalSupply += 1; // Sem proteção contra overflow
    }

    function decrementarSupply() public {
        totalSupply -= 1; // Sem proteção contra underflow
    }
}
