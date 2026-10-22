# openiec61850

Biblioteca clean-room da norma IEC 61850 com núcleo nativo de alta performance e API Python de primeira classe.

## Linguagem

### Projeto

**Paridade de binding**:
Garantia de que toda funcionalidade pública do núcleo nativo existe também na API Python, sem nada exclusivo do nativo.
_Evite_: "100% de compatibilidade", compatibilidade pybind

**Camada de compatibilidade pyiec61850**:
Pacote separado e opcional que imita a API do binding SWIG da libiec61850 para migrar código legado; não faz parte do núcleo.
_Evite_: modo compatível, drop-in

**Benchmark de referência**:
Medição comparativa entre openiec61850 e libiec61850 na mesma máquina, que serve como critério oficial de "performático".
_Evite_: teste de performance (genérico)

### Papéis de comunicação

**Cliente**:
Papel ACSI que estabelece uma associação com um Servidor via MMS sobre a pilha ISO/TCP e invoca serviços nele.
_Evite_: master, assinante

**Servidor**:
Papel ACSI exercido por um IED que expõe seu modelo de dados e atende a serviços de Clientes via MMS.
_Evite_: slave, publicador

**Assinante**:
Papel que recebe mensagens multicast de camada 2 (GOOSE ou SV) de um Publicador, sem associação.
_Evite_: cliente GOOSE, subscriber de MMS

**Publicador**:
Papel que emite mensagens multicast GOOSE ou SV.
_Evite_: servidor GOOSE

**Associação**:
Sessão lógica estabelecida entre um Cliente e um Servidor, dentro da qual os serviços são invocados.
_Evite_: conexão (quando se fala do nível ACSI)

**Camada ACSI**:
Nível da API que fala em termos da IEC 61850 (Associação, LD/LN/DO/DA, RCB, controle, setting groups etc.).
_Evite_: API de alto nível

**Camada MMS genérica**:
Nível da API que fala em termos da ISO 9506 (domínios, variáveis nomeadas, GetNameList, Read/Write), sem semântica IEC 61850; é pública para diagnóstico e para Servidores não conformes.
_Evite_: API de baixo nível, raw MMS

### Modelo de dados no Cliente

**Valor MMS**:
Representação genérica e sem tipo de modelo de um dado trafegado em MMS (estrutura, array, inteiro, float, bit-string, UtcTime etc.).
_Evite_: MmsValue (nome da libiec61850)

**Modelo descoberto**:
Árvore navegável do modelo de dados de um Servidor (LD/LN/DO/DA), construída em tempo de execução por meio dos serviços de diretório e de definição.
_Evite_: modelo dinâmico, cache

**Modelo SCL**:
Modelo de dados de um Servidor obtido offline de um arquivo SCL (ICD/CID/SCD), em vez da descoberta online.
_Evite_: modelo estático

**Quality**:
Atributo de qualidade associado a um dado (validade, fonte, teste, operador bloqueado etc.), conforme a IEC 61850-7-3.
_Evite_: status, flags

**Timestamp**:
Instante UtcTime da IEC 61850 com fração de segundo e qualidade de tempo (precisão, leap second, sincronismo).
_Evite_: datetime, hora

### Reporting

**RCB**:
Bloco de controle de report no Servidor que define o que é reportado ao Cliente e como; pode ser bufferizado (BRCB) ou não bufferizado (URCB).
_Evite_: subscription, assinatura de report

**Report**:
Mensagem não solicitada que o Servidor envia ao Cliente quando um RCB habilitado é disparado.
_Evite_: evento, notificação

**EntryID**:
Identificador de uma entrada no buffer de um BRCB, usado para retomar o fluxo de reports sem perda após uma interrupção.
_Evite_: sequence number (SqNum é outra coisa)

**Restauração de associação**:
Recuperação automática, e opcional, de uma Associação perdida: reconexão e reabilitação dos RCBs, com retomada dos BRCBs a partir do último EntryID recebido.
_Evite_: auto-reconnect (que sugere só reconexão TCP)

**Edição do Servidor**:
Edição da IEC 61850 (Ed.1, Ed.2 ou Ed.2.1) que o Servidor implementa e que altera a semântica de alguns serviços e blocos de controle.
_Evite_: versão
