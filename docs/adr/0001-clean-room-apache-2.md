# Implementação clean-room sob Apache-2.0

A libiec61850 (MZ Automation) é GPLv3 ou comercial. A openiec61850 é implementada só a partir do texto da norma IEC 61850 (e das normas ISO/MMS referenciadas), sem ler nem portar código da libiec61850, e é licenciada como Apache-2.0. Assim ela pode ser usada em produtos fechados, que é o principal diferencial frente à libiec61850.

## Consequências

- Contribuidores não podem copiar trechos nem "traduzir" funções da libiec61850.
- Rodar binários da libiec61850 como par de teste de interoperabilidade e nos benchmarks é permitido, já que é execução, não derivação de código.
