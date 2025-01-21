// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract DoacaoELoteria is Ownable {
    // Lista de doadores
    address[] private doadores;
    mapping(address => uint256) public doacoes;
    uint256 public totalDoacoes;

    // Evento para registrar sorteios
    event VencedorSelecionado(address vencedor, uint256 premio);

    // Construtor que passa o proprietário inicial para o contrato Ownable
    constructor(address proprietarioInicial) Ownable(proprietarioInicial) {}

    // Função para realizar doações
    function doar() public payable {
        require(msg.value > 0, "A doacao deve ser maior que zero");
        if (doacoes[msg.sender] == 0) {
            doadores.push(msg.sender); // Adiciona novo doador à lista
        }
        doacoes[msg.sender] += msg.value; // Registra o valor doado
        totalDoacoes += msg.value; // Atualiza o total
    }

    // Função para realizar o sorteio (apenas o proprietário pode chamar)
    function realizarSorteio() public onlyOwner {
        require(doadores.length > 0, "Nenhum doador registrado");
        address vencedor = _selecionarVencedorAleatorio();
        uint256 premio = totalDoacoes;

        _resetarDoacoes(); // Reseta o estado interno após o sorteio
        payable(vencedor).transfer(premio);

        emit VencedorSelecionado(vencedor, premio);
    }

    // Função privada para selecionar um vencedor aleatório
    function _selecionarVencedorAleatorio() private view returns (address) {
        uint256 indiceAleatorio = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, doadores))
        ) % doadores.length;
        return doadores[indiceAleatorio];
    }

    // Função privada para resetar doações
    function _resetarDoacoes() private {
        for (uint256 i = 0; i < doadores.length; i++) {
            doacoes[doadores[i]] = 0;
        }
        delete doadores;
        totalDoacoes = 0;
    }

    // Função para visualizar os doadores (somente o proprietário pode consultar)
    function obterDoadores() public view onlyOwner returns (address[] memory) {
        return doadores;
    }
}