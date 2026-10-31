# Critérios do release alfa 0.1.0

"Pronta" passou a significar uma meta verificável: o `0.1.0` é um Release alfa público no PyPI e no GitHub, com API instável e sem declaração de conformidade. Só há tag com o CI do GitLab verde, a suíte de interop com a libiec61850 verde nos dois sentidos, as wheels Linux x86_64 e aarch64 construídas e a confirmação explícita do mantenedor, porque uma versão publicada no PyPI não pode ser republicada.

Dois pontos são dispensados de propósito. O IEC61850bean, previsto no ADR 0007, não bloqueia o alfa: exigir só a libiec61850 dá validação independente nos dois sentidos sem atrasar o primeiro release. O TLS é validado contra o `openssl` como par independente, pois a suíte da libiec61850 não o cobre.

## Consequências

- O CHANGELOG lista o que não foi verificado: trechos escritos sem o texto da norma, como a codificação do ObtainFile, a forma `(n)` em DataRef e as cifras da IEC 62351-3, e a falta de interop de TLS com outra implementação IEC 61850.
- A assinatura de GOOSE/SV (IEC 62351-6) e a autenticação por certificado na ACSE (IEC 62351-4) ficam de fora, e são limitações conhecidas.
- macOS e Windows não bloqueiam o release.
- Sem o Benchmark de referência, nenhum material do projeto promete desempenho até o `1.0`.
