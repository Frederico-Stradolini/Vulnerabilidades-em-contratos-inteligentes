# Guia de segurança em contratos inteligentes
Os contratos inteligentes são a base de tecnologias emergentes como blockchain e Web3, permitindo a execução automática de acordos digitais sem a necessidade de intermediários. No entanto, sua crescente popularidade trouxe à tona desafios significativos relacionados à segurança. Vulnerabilidades em contratos inteligentes podem resultar em perdas financeiras, comprometimento de dados e falhas de integridade em aplicações descentralizadas (dApps).

Este guia foi elaborado para explorar as principais vulnerabilidades que afetam os contratos inteligentes, desde problemas como ataques de reentrância até falhas de validação de entrada. Veremos como é um código vulnerável e as estratégias necessárias para mitigas os riscos de ataques ao contrato.

Você pode navegar facilmente entre as seções clicando nos links abaixo:

- [Reentrancy](#reentrancy)
- [Overflow e Underflow](#overflow-e-underflow)
- [Gas limit e DoS](#gas-limit-e-dos)
- [Exposição de funções sensíveis](#exposição-de-funções-sensíveis)

## Reentrancy
O ataque de reentrância ocorre quando uma função de um contrato inteligente realiza uma chamada externa para outro contrato antes de finalizar sua própria execução. Durante essa chamada externa, o contrato chamado pode, de forma maliciosa, invocar novamente a função original, explorando o estado parcial ou incompleto do primeiro contrato.

### Como funciona o ataque

1. **Chamada externa vulnerável**: Um contrato realiza uma chamada externa, geralmente para transferir fundos ou interagir com outro contrato.

2. **Estado inconsistente**: Antes de atualizar seu próprio estado interno, o contrato deixa brechas que permitem que a chamada externa execute novamente a função vulnerável.

3. **Reentrada**: O contrato externo malicioso aproveita essa oportunidade para invocar novamente a função original, explorando o estado inconsistente repetidas vezes antes que ele seja corrigido.

4. **Exaustão de recursos**: Esse ciclo de reentradas pode drenar fundos ou causar alterações inesperadas no estado do contrato vulnerável.


**O código abaixo exemplifica um contrato vulnerável a reentrada:**
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ContratoVulneravel {
    mapping(address => uint256) public saldo;

    function depositar() public payable {
        saldo[msg.sender] += msg.value; // Adiciona o valor depositado ao saldo
    }

    function sacar(uint256 _amount) public {
        require(saldo[msg.sender] >= _amount, "Saldo insuficiente");

        // Chamada externa que pode ser explorada para reentrancy
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transferencia falhou");

        // Atualização do saldo ocorre após a chamada externa
        saldo[msg.sender] -= _amount; 
    }
}
```
O contrato começa com a definição de um mapeamento `saldo` para armazenar o saldo de cada endereço. A função `depositar` permite que os usuários enviem Ether para o contrato. Quando um usuário deposita, o valor enviado é adicionado ao `saldo` registrado para o endereço correspondente no mapeamento.

A função `sacar` permite que os usuários retirem Ether de seu saldo. Antes de proceder, a função verifica se o usuário tem saldo suficiente. Se a verificação for bem-sucedida, a função tenta transferir a quantidade solicitada ao usuário utilizando a função `call`. Isso é feito antes de atualizar o `saldo` do usuário no contrato.

A vulnerabilidade de reentrância surge aqui. Quando o contrato chama a função `call` para enviar os fundos ao usuário, o contrato de destino (o endereço do usuário) pode executar novamente a função `sacar`. Isso ocorre antes do `saldo` ser atualizado no contrato, permitindo que o atacante saque mais Ether do que o saldo original, explorando a falha repetidamente.

Para garantir que o contrato seja seguro contra reentrada, devem ser feitas as seguintes mudanças:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ContratoVulneravel {
    bool private locked; // Variável que ajuda a prevenir a reentrância, controlando se a função está em execução

    mapping(address => uint256) public saldo;

    // Modificador que impede reentrância em funções que o utilizam
    modifier noReentrancy() { 
        require(!locked, "Sem reentrancia permitida"); // Verifica se o contrato já está em execução
        locked = true; // Bloqueia a execução de chamadas subsequentes
        _; // Continuar com a execução da função
        locked = false; // Desbloqueia a execução após a função terminar
    }

    function depositar() public payable {
        saldo[msg.sender] += msg.value; // Adiciona o valor enviado ao saldo do usuário
    }

    function sacar(uint256 _amount) public noReentrancy {
        require(saldo[msg.sender] >= _amount, "Saldo insuficiente");

        saldo[msg.sender] -= _amount; // Atualiza o saldo do usuário
        (bool success, ) = msg.sender.call{value: _amount}(""); // Realiza a transferência de Ether para o usuário
        require(success, "Transferencia falhou");
    }
}
```
Antes de analisar o novo código, é importante compreender o conceito de `modifier`: trata-se de um bloco de código reutilizável que pode ser empregado para alterar o comportamento de uma função ou adicionar lógica antes e/ou depois de sua execução. Os `modifiers` são úteis para implementar verificações ou restrições de maneira sistemática e eficiente.

O contrato começa com a definição de uma variável `locked`, que controla se a função está em execução ou não. Essa variável é usada como uma forma de prevenção contra reentrância. Quando uma função que utiliza o modificador `noReentrancy` é chamada, a variável `locked` é definida como `true`, bloqueando a execução de chamadas subsequentes. Após a execução da função, a variável é configurada para `false`, permitindo novas execuções.

A outra modificação efetuada foi na função `sacar`, que inclui o `modifier` `noReentrancy`. Adicionando a lógica de bloqueio antes da execução da função e libera o bloqueio após sua conclusão. Além disso, a atualização do saldo através do `saldo[msg.sender] -= _amount` foi antecipada para ocorrer antes da chamada externa, eliminando completamente a possibilidade de ataques de reentrância

## Overflow e Underflow
O ataque de overflow e underflow ocorre quando um contrato inteligente realiza operações aritméticas sem as devidas verificações de limites, resultando em comportamentos inesperados ao manipular números. Essas falhas podem ser exploradas por um atacante para alterar o estado do contrato de maneira prejudicial.

### Como funciona o ataque
O **overflow** ocorre quando um valor numérico ultrapassa o valor máximo que pode ser armazenado no tipo de dado utilizado. Por exemplo, em Solidity, o tipo `uint8` armazena números inteiros sem sinal de 0 a 255. Se um valor maior que 255 for adicionado a uma variável do tipo `uint8`, ela "transbordará" e voltará para o valor mínimo, que é 0.

O **underflow** ocorre quando um valor numérico é subtraído a ponto de se tornar menor que o valor mínimo permitido para o tipo de dado. No caso de variáveis `uint`, o valor mínimo é 0. Se uma operação de subtração resultar em um valor negativo, isso causará um underflow, e o número voltará ao valor máximo que o tipo de dado pode armazenar.

**O código abaixo exemplifica um contrato vulnerável a overflow e underflow:**
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.7.0; 
// Versão anterior a ^0.8.0, onde não há proteção automática contra overflow e underflow

contract ContratoNaoSeguro {
    uint256 public totalSupply;

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
```
No exemplo mostrado, quando o `totalSupply` é 255 (o máximo para `uint8`) e a função `incrementSupply` é chamada, ocorre um overflow, retornando o valor para 0. Se o `totalSupply` for 0 e a função `decrementarSupply` for chamada, ocorre um underflow, resultando no valor máximo permitido (255). 

A partir da versão 0.8.0 do Solidity, verificações automáticas de overflow e underflow foram introduzidas. Operações que excedem os limites de capacidade resultam na reversão automática da transação. A única modificação necessário é na versão do compilador Solidity:
```solidity
pragma solidity ^0.8.0;
```
Caso seja necessário que o contrato seja executado em versões anteriores ao Solidity 0.8.0, bibliotecas como SafeMath, que realizam verificações manuais para operações aritméticas,  são eficientes para prevenir estes problemas. O contrato com utilização desta biblioteca fica desta forma:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.7.0; 
// Versões ^0.8.0 garantem segurança contra overflow e underflow sem necessidade do SafeMath

import "@openzeppelin/contracts/math/SafeMath.sol";

contract ContratoSeguro {
    using SafeMath for uint8;
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
```
Para realizar a importação da biblioteca SafeMath em compiladores online como o Remix, pode ser utilizado `import "@openzeppelin/contracts/math/SafeMath.sol"`. Na definição do contrato é especificado que a biblioteca SafeMath será aplicada para operações envolvendo dados do tipo `uint8`.

Para a execução de operações matemáticas usam-se os métodos da biblioteca, como o `add` e o `sub`, evitando que ocorra overflow ou underflow.
