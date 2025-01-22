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
O ataque de reentrância ocorre quando um contrato realiza uma chamada externa, geralmente para transferir fundos ou interagir com outro contrato. Antes de atualizar seu próprio estado interno, o contrato deixa brechas que permitem que a chamada externa execute novamente a função vulnerável.

O contrato externo malicioso aproveita essa oportunidade para invocar novamente a função original, explorando o estado inconsistente repetidas vezes antes que ele seja corrigido. Esse ciclo de reentradas pode drenar fundos ou causar alterações inesperadas no estado do contrato vulnerável.

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
Antes de analisar o novo código, é importante compreender o conceito de `modifier`: trata-se de um bloco de código reutilizável que pode ser empregado para alterar o comportamento de uma função ou adicionar lógica antes e/ou depois de sua execução. O caractere `_` indica onde será feita a execução da função, para aplicar o `modifier` em uma função deve-se declará-lo assim como no exemplo. Os `modifiers` são úteis para implementar verificações ou restrições de maneira sistemática e eficiente.

O contrato começa com a definição de uma variável `locked`, que controla se a função está em execução ou não. Essa variável é usada como uma forma de prevenção contra reentrância. Quando uma função que utiliza o modificador `noReentrancy` é chamada, a variável `locked` é definida como `true`, bloqueando a execução de chamadas subsequentes. Após a execução da função, a variável é configurada para `false`, permitindo novas execuções.

A outra modificação efetuada foi na função `sacar`, que inclui a declaração do `modifier` `noReentrancy`. Adicionando a lógica de bloqueio antes da execução da função e libera o bloqueio após sua conclusão. Além disso, a atualização do saldo através do `saldo[msg.sender] -= _amount` foi antecipada para ocorrer antes da chamada externa, eliminando completamente a possibilidade de ataques de reentrância

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
    uint8 public totalSupply;

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
Para realizar a importação da biblioteca SafeMath em compiladores online como o Remix, pode ser utilizado `import "@openzeppelin/contracts/math/SafeMath.sol"`. Na definição do contrato é especificado que a biblioteca SafeMath será aplicada para operações envolvendo dados do tipo `uint256`.

Para a execução de operações matemáticas usam-se os métodos da biblioteca, como o `add` e o `sub`, evitando que ocorra overflow ou underflow.

## Gas limit e DoS
O gás em blockchain é a taxa cobrada para realizar transações ou executar contratos na rede, é um incentivo para que os validadores de rede registrem transações com precisão e se comportem honestamente.

### Como funciona o ataque
Cada bloco possui um limite de gás, que é a quantidade máxima de gás que pode ser utilizada em um único bloco. Se uma função em um contrato inteligente exigir mais gás do que o limite de gás do bloco para completar sua execução, a transação falhará. Falhas como esta são comuns em loops que iteram sobre dados dinâmicos, que podem creser arbitrariamente.

Além disso, contratos inteligentes podem sofrer ataques de negação de serviço (DoS) que visam interromper suas operações normais, exlporando loops que consomem uma quantidade excessiva de gás. Um exemplo típico de DoS ocorre quando um contrato exige iterações sobre uma lista de elementos para completar uma tarefa. Caso o atacante consiga adicionar elementos excessivos à lista ou manipular a lógica do contrato, ele pode causar o consumo de todo o gás disponível, impedindo a execução bem-sucedida da função. 

**O código abaixo exemplifica um contrato vulnerável a gas limit e DoS:**
```solidity
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
```
O loop for percorre toda a lista de destinatários sem considerar o consumo de gás, o que pode se tornar um problema grave caso a lista seja muito grande. Nesse cenário, o consumo de gás pode exceder o limite permitido pelo bloco, resultando na falha da transação. Além disso, a função não mantém um estado persistente que registre o progresso dos pagamentos, como um índice dos destinatários já processados. Isso implica que, em caso de falha, a execução precisa recomeçar do início, desperdiçando ainda mais gás.

Para que o contrato seja seguro contra essas vulnerabilidades é necessário fazer as seguintes alterações:
```solidity
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
```
Um dos elementos principais dessa abordagem é o uso do parâmetro `tamanhoLote`, diretamente na função `pagamento`,  que limita o número de destinatários processados em uma única execução. Isso garante que o processamento seja controlado e evita que loops muito longos consumam mais gas do que o permitido pelo bloco, reduzindo significativamente o risco de falhas por excesso de consumo. O parâmetro `tamanhoLote` deve ser informado pelo usuário ou definido automáticamente na lógica do backend da aplicação.

Além disso, o controle de gas é aprimorado pelo uso da função `gasleft()`, que interrompe a execução do loop caso o gas restante esteja abaixo de um limite seguro, oferecendo uma camada adicional de proteção. 

O contrato também implementa o processamento por partes, utilizando um índice persistente `indiceProximo`, para armazenar o progresso. Isso permite que os pagamentos sejam realizados em várias transações, retomando do ponto em que pararam, o que elimina a necessidade de reiniciar todo o processo em caso de interrupção.

## Exposição de funções sensíveis
A exposição de funções sensíveis em contratos inteligentes acontece quando funções críticas ficam acessíveis de forma inadequada, permitindo que usuários não autorizados as utilizem. Essas funções, frequentemente, têm o poder de alterar estados importantes do contrato ou gerenciar fundos, tornando-se alvos atraentes para atacantes mal-intencionados.

### Como funciona o ataque
Quando funções que alteram o estado do contrato, transferem fundos ou realizam outras operações críticas estão disponíveis para qualquer usuário, sem restrições adequadas, qualquer pessoa terá o direito de invocá-las, podendo retirar fundos, alterar configurações importantes, destruir o contrato ou redefinir estados críticos. 

Para este tipo de vulnerabilidade usaremos um exemplo diferente. O contrato a seguir já possui boas práticas de desenvolvimento que mitigam a exposição de funções sensíveis:
```solidity
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
```
A variável `doadores` é definida como privada, pois não deve ser acessada por todos os usuários.

O evento `VencedorSelecionado` é emitido após o sorteio, permitindo rastrear publicamente os resultados. Inclui informações sobre o vencedor e o valor do prêmio, aumentando a transparência e confiabilidade do processo.

No `constructor` é definido o proprietário do contrato, no caso, onde está escrito `proprietarioInicial` deve ser informado um endereço Ethereum, que é uma sequência de carácteres usada para identificar contas na blockchain. Normalmente, o proprietário é definido no momento da implantação do contrato, como o endereço que implantou o contrato, mas também pode ser feito através do `contructor`.

A função `doar` deve ser acessível a todos usuários, logo é definida como pública.

`realizarSorteio` pode ser chamada apenas pelo dono do contrato, por isso foi declarada como `OnlyOwner`, uma funcionalidade da biblioteca Ownable, que restringe o acesso a funções apenas ao proprietário do contrato.

`_selecionarVencedorAleatorio` e `_resetarDoacoes` são declaradas como privadas pois servem apenas como lógica interna do contrato, não precisam ser acessadas externamente.

Por fim, a função `obterDoadores` é declarada como uma `view`, um tipo de função que não altera o estado do contrato e nem consome gas. Também possui a funcionalidade `OnlyOwner` e só pode ser chamada pelo proprietário do contrato.

## Ataques diretamente a usuários
Embora esse tipo de ataque não envolva diretamente o código desenvolvido, é fundamental que os desenvolvedores compreendam os tipos de ataques mais comuns direcionados aos usuários. Ao adquirir esse conhecimento, os desenvolvedores podem ajudar a conscientizar seus usuários para evitar cair em golpes. Mesmo que o ataque não afete diretamente a plataforma, se um usuário for vítima de um golpe em que o atacante se passa pela empresa, isso pode resultar em danos significativos à reputação. Quanto mais informados os usuários estiverem e mais intuitiva for a interface, menores serão os riscos de eles caírem em fraudes.

### Front-running

### Roubo de chave privada

### Phishing

### Rug Pull

### Erros na interace do usuário
