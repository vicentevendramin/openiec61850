# Núcleo em C++20 com bindings nanobind

O núcleo é escrito em C++20 e exposto ao Python com nanobind, que tem menos overhead por chamada e binários menores que o pybind11.

## Opções consideradas

- **Rust + PyO3**: segurança de memória no parser de rede e empacotamento mais simples. Foi preterido pela familiaridade da equipe com C++ e pelo ecossistema de automação, que é majoritariamente C/C++.
- **Go**: rejeitado como extensão Python. Teríamos dois runtimes no mesmo processo (scheduler Go + GIL), só um runtime Go por processo e callbacks Go→Python caros e cheios de restrições de cgo.

## Consequências

Como a segurança de memória não vem do compilador, o decodificador BER/MMS precisa de fuzzing contínuo e de sanitizers (ASan/UBSan) no CI desde o primeiro dia.
