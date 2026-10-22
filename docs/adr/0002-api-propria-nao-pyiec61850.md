# API própria em vez de compatibilidade com pyiec61850

O "100% de compatibilidade" foi definido como paridade de binding: toda a API nativa existe em Python. Não é compatibilidade com a API C da libiec61850 nem com o pyiec61850. Imitar os handles opacos e os parâmetros de erro de saída da API C prenderia o núcleo a um desenho que limita a performance e é pouco pythônico. Se houver código legado para migrar, ele será atendido por uma camada de compatibilidade pyiec61850 separada e opcional.
