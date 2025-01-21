// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ContratoVulneravel {
    // Estrutura que define um destinatário e o valor a ser pago
    struct Beneficiario {
        address addr;
        uint256 value;
    }

    Beneficiario[] public destinatarios; // Lista de destinatários

    // Função para adicionar um destinatário à lista
    function addBenefeciario(address _addr, uint256 _value) external {
        require(_addr != address(0), "Endereco invalido");
        require(_value > 0, "O valor deve ser maior que zero");
        destinatarios.push(Beneficiario({addr: _addr, value: _value}));
    }

    // Função de pagamento vulnerável
    function pagamento() external {
        for (uint256 i = 0; i < destinatarios.length; i++) {
            // Tenta enviar o valor para o destinatário
            (bool success, ) = destinatarios[i].addr.call{value: destinatarios[i].value}("");
            require(success, "Transferencia falhou");
        }
    }
}