# Interoperabilidade validada sem IEDs físicos

O projeto não tem acesso a IEDs físicos. O CI valida a interoperabilidade contra duas implementações independentes rodando no homelab: os servidores de exemplo da libiec61850, executados como binário (o que o ADR 0001 permite), e o servidor do IEC61850bean. Simuladores comerciais em licença trial e capturas pcap públicas de tráfego MMS real complementam essa validação: os simuladores são usados em testes manuais e as capturas entram como corpus de regressão e de fuzzing.

## Consequências

Comportamentos não conformes de fabricantes específicos, comuns em servidores Ed.1, só aparecerão em campo. Esse risco é aceito, e os relatos de campo devem virar casos no corpus de regressão.
