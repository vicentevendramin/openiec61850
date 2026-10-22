# Núcleo assíncrono com fachada síncrona

O Cliente roda sobre um núcleo assíncrono com uma thread de I/O própria que nunca segura o GIL. Em Python, a API `asyncio` é a de primeira classe e há um wrapper síncrono fino por cima dela. Reports chegam como async iterator, com callback opcional. Rejeitamos o modelo só bloqueante com threads de callback, estilo libiec61850, porque ele não escala para muitas associações e muitos pedidos em paralelo dentro de uma mesma associação.
