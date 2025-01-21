// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ContratoSeguro {
    struct Beneficiario {
        address addr;
        uint256 value;
    }

    Beneficiario[] public destinatarios;
    uint256 public indiceProximo; // Índice do próximo destinatário a ser processado

    function addBeneficiario(address _addr, uint256 _value) external {
        require(_addr != address(0), "Endereco invalido");
        require(_value > 0, "O valor deve ser maior que zero");
        destinatarios.push(Beneficiario({addr: _addr, value: _value}));
    }

    function pagamento(uint256 tamanhoLote) external {
        require(tamanhoLote > 0, "O tamanho do lote deve ser maior que zero");

        uint256 i = indiceProximo; // Começa no índice do próximo destinatário
        uint256 fim = i + tamanhoLote; // Define o limite baseado no tamanho do lote

        while (i < fim && i < destinatarios.length && gasleft() > 200000) {
            Beneficiario memory beneficiario = destinatarios[i];

            // Tenta enviar o valor para o destinatário
            (bool success, ) = beneficiario.addr.call{value: beneficiario.value}("");
            require(success, "Transferencia falhou");

            i++; // Avança para o próximo destinatário
        }

        indiceProximo = i; // Índice persistente do próximo destinatário
    }
}