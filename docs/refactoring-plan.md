# Plano incremental de reorganização

## Referência e objetivo

Referência inicial: `40b60906dfa299309fd423022bb00225666d7ff6`, tag
`baseline/pre-refactor-2026-11-12`. A CI dessa versão aprovou 794 testes e a
suíte de falhas 18/18. O [inventário](reference-baseline.json) e o
[guia de reprodução](reproducibility.md) delimitam o que essa referência contém.

O objetivo é tornar o código ativo mais fácil de entender, testar e manter,
preservando as versões necessárias para reproduzir a pesquisa. A reorganização
não altera critérios de promoção nem aprova resultados experimentais.

## Etapas e critérios de conclusão

| Etapa | Entrega | Critério |
| --- | --- | --- |
| 1 — Documentação e referência | README curto, manual preservado, índice, mapa da arquitetura, política de reprodução e inventário Git. | Links locais válidos; nenhum arquivo de código, modelo, configuração ou contrato alterado. |
| 2 — Fronteiras do runtime | Mapa de dependências e extração gradual de configuração, coleta, previsão e API. | Comparações de comportamento e verificações existentes aprovadas por extração. |
| 3 — Armazenamento e coordenação | Interfaces explícitas para leitura/publicação, relógio e transporte; autoridade separada da composição do serviço. | Preservados quórum, TTL, snapshots, commit desconhecido e exclusão do executor. |
| 4 — Pesquisa e comandos | Navegação uniforme para treino, backtest, campanhas e relatórios; resolução explícita das versões históricas. | Comandos existentes continuam disponíveis no seu checkout de origem; saídas antigas reproduzíveis. |
| 5 — CI e distribuição | Jobs rápidos e reprodução completa identificados separadamente; empacotamento e dependências por componente. | Mesma cobertura exigida; imports sem efeitos de runtime; compatibilidade verificada com as versões Python suportadas. |

A etapa 1 é o escopo da primeira mudança. As demais etapas exigem alterações de
código e evidências próprias; os diretórios propostos abaixo ainda não existem.

## Destino proposto para o código ativo

```text
src/comas/
  runtime/       composição do serviço e configuração
  telemetry/     contadores, qualidade e históricos
  forecasting/   modelos e estado dos previsores
  detection/     resíduos, anomalias e deduplicação
  coordination/  propostas, deliberação, autoridade e claims
  storage/       interfaces e clientes de armazenamento
  api/           rotas e serialização HTTP
research/        novas entradas de treino, campanhas e análises
docs/            navegação, arquitetura e operação
tests/           testes organizados pelas mesmas responsabilidades
```

Essa árvore é uma proposta, não uma lista de movimentações a executar de uma
vez. `llm_auditor/` já tem uma fronteira própria e pode permanecer como pacote
independente. Os serviços Ryu, SimpleSwitch e FlowBlocker também mantêm seus
contextos de build enquanto essa separação for necessária.

## Sequência para o runtime

1. Mapear constantes de configuração, dependências externas e efeitos de import
   de `flow_predictor_cnsm.py`.
2. Separar funções e modelos puros, com testes de equivalência focados nos
   estados e decisões observáveis.
3. Introduzir composição explícita para relógio, transporte, armazenamento e
   coleta. Importar uma biblioteca não deve iniciar o serviço.
4. Extrair a API e a orquestração, preservando endpoints, payloads e defaults.
5. Atualizar o Dockerfile e os comandos somente junto da verificação do novo
   caminho de execução.

Arquivos protegidos por protocolos antigos permanecem disponíveis pela versão
registrada. Criar wrappers nos mesmos caminhos muda seus hashes e não resolve
sozinho a compatibilidade dos experimentos.

## Organização no GitHub

- Revisar o PR que integra a evolução de pesquisa antes de atualizar `main`.
- Usar branches curtas por responsabilidade e descrever a base de PRs empilhados.
- Registrar tags de referência que apontem para commits testados; uma tag de
  baseline não deve ser apresentada como uma release de produção.
- Tratar remoção de branches como uma ação posterior à conferência dos commits
  já integrados e das referências usadas pelos experimentos.
- Manter a documentação de estado separada das métricas de um experimento.
  Resultados brutos e backups não entram em commits de reorganização.

Nenhum merge, exclusão de branch, mudança de proteção ou implantação faz parte
da primeira etapa documental.
