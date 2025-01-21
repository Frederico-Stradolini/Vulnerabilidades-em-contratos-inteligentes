// SPDX-License-Identifier: MIT

pragma solidity ^0.7.0; 
// Versões ^0.8.0 garantem segurança contra overflow e underflow sem necessidade do SafeMath

import "@openzeppelin/contracts/math/SafeMath.sol";

contract ContratoSeguro {
    using SafeMath for uint256;
    uint256 public totalSupply;

    constructor() {
        totalSupply = 255;
    }

    function incrementarSupply() public {
        totalSupply = totalSupply.add(1); // Garante segurança contra overflow
    }

    function decrementarSupply() public {
        totalSupply = totalSupply.sub(1); // Garante segurança contra underflow
    }
}
