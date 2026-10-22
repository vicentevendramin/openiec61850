# Desenvolvimento no GitLab self-hosted, releases no GitHub

O desenvolvimento e o CI rodam num GitLab self-hosted no homelab do mantenedor, porque é lá que estão os containers, as VMs e os servidores de teste de interoperabilidade (servidores da libiec61850, simuladores). O GitHub recebe espelhamento e os releases oficiais (tags, wheels publicadas no PyPI). A definição do CI é a do GitLab (`.gitlab-ci.yml`), e o GitHub Actions, se existir, se limita ao que precisa rodar do lado público, como publicação e verificações de PR externos.

## Consequências

- Contribuições externas chegam por PRs no GitHub e precisam ser trazidas para o GitLab. Esse fluxo de sincronização precisa ser definido antes de aceitar o primeiro PR externo.
- Jobs que dependem da infraestrutura do homelab (testes de interoperabilidade, fuzzing longo) não rodam para contribuidores externos.
