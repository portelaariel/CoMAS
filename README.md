# CoMAS — Coordinated Multi-Domain Agent-Based defense for SDN

[![Repository validation](https://github.com/portelaariel/CoMAS/actions/workflows/validate.yml/badge.svg)](https://github.com/portelaariel/CoMAS/actions/workflows/validate.yml)

CoMAS é um framework de pesquisa para observar tráfego SDN, prever seu
comportamento, detectar anomalias e coordenar decisões entre domínios. O testbed
usa Ryu, Open vSwitch, Mininet e ETCD. Uma linha experimental separada estuda a
antecipação de violações de SLA a partir de séries de utilização de portas.

**Comece pelo [guia inicial](docs/getting-started.md).** O
[manual operacional completo](docs/operations.md) reúne instalação, execução,
configuração, treinamento, API e solução de problemas.

## Estado dos componentes

| Componente | O que existe | Escopo atual |
| --- | --- | --- |
| Detecção de tráfego | Modelo offline, previsão Holt e detecção por resíduos | Estudos de tráfego volumétrico no laboratório. |
| Coordenação entre domínios | MCDA observacional, agentes determinísticos, gate de autoridade e claim atômico | Modos shadow, authority-dry-run e authority-live com condições explícitas. |
| Previsão de SLA | Telemetria QoS, modelos multi-horizonte, campanhas offline e pilotos online shadow | Linha experimental; a validação prospectiva v4 permanece `NOT_PASSED`. |
| Auditoria | Verificação determinística de eventos, certificados e explicações opcionais via LLM | Análise pós-experimento; a LLM não decide nem autoriza atuação no runtime. |
| Infraestrutura | Scripts de setup, coleta, diagnóstico e recuperação controlada | Ferramentas do testbed; alguns procedimentos são específicos do laboratório. |

O modo `authority-live` pode instalar regras DROP reais. As instruções iniciais
usam dry-run. Aprovação de testes de software, consistência de um certificado e
aprovação experimental são resultados distintos.

## Documentação

| Necessidade | Documento |
| --- | --- |
| Escolher entre uso offline e laboratório | [Guia inicial](docs/getting-started.md) |
| Entender componentes, fluxos e fronteiras | [Arquitetura atual](docs/architecture.md) |
| Instalar, operar e diagnosticar | [Manual operacional](docs/operations.md) |
| Reproduzir resultados e preservar artefatos congelados | [Reprodutibilidade](docs/reproducibility.md) |
| Consultar as fases e protocolos de SLA | [Pipeline experimental de SLA](PREDICTIVE_SLA.md) |
| Auditar eventos e usar certificados | [LLM Auditor](llm_auditor/README.md) |
| Gerar narrativas suplementares dos agentes | [Explicações dos agentes](llm_auditor/AGENT_EXPLANATION.md) |
| Recuperar o membro ETCD do laboratório e observar latências | [Recuperação controlada](scripts/README_etcd2_recovery.md) |
| Consultar o plano condicional de armazenamento | [Plano de armazenamento ETCD](scripts/ETCD_STORAGE_PLAN.md) |
| Contribuir e validar mudanças | [Contribuição](CONTRIBUTING.md) |
| Acompanhar a reorganização | [Plano incremental](docs/refactoring-plan.md) |

O [índice da documentação](docs/README.md) relaciona esses documentos por tarefa.

## Verificação local

Na raiz do repositório:

```bash
bash scripts/validate_repository.sh
```

A verificação usa testes e simulações locais; não inicia Docker nem Mininet.
A suíte completa inclui reprodução de fixtures congeladas e pode levar cerca
de vinte minutos ou mais, conforme a máquina. O workflow do GitHub reserva até
sessenta minutos para concluí-la.

Para consultar a CLI de auditoria:

```bash
python3 -m llm_auditor --help
```

As dependências do runtime Docker e os requisitos do laboratório são descritos
no manual operacional. A verificação de software não substitui as campanhas de
rede.

## Mapa do repositório

| Caminho | Responsabilidade |
| --- | --- |
| `flow_predictor_cnsm.py` | Composição atual do serviço: coleta, detecção, coordenação e API. |
| `agent_protocol.py`, `domain_agent.py`, `agent_authority.py` | Propostas, deliberação, autorização e claim. |
| `offline_model.py`, `qos_*.py`, `sla_*.py` | Contratos de modelos, previsão, telemetria e avaliação de risco. |
| `predictive_sla_*.py`, `train_*.py`, `backtest_sla_risk.py` | Entradas de treinamento, campanhas e análises de pesquisa. |
| `llm_auditor/` | Auditoria determinística e interfaces opcionais com Ollama. |
| `ryu_apps/`, `rest_client/`, `flow_blocker/` | Serviços do plano de controle e atuação. |
| `config/`, `eMSN_ENV/`, `scripts/` | Configuração e ferramentas operacionais. |
| `experiments/`, `tests/`, `models/` | Avaliadores, testes e modelos incluídos. |
| `docs/`, `.github/` | Documentação e colaboração no GitHub. |

Essa é a organização física atual. O plano propõe extrair módulos gradualmente;
os scripts históricos continuam em seus caminhos originais.

## Versão de referência para a reorganização

O commit `40b60906dfa299309fd423022bb00225666d7ff6`, identificado pela tag
`baseline/pre-refactor-2026-11-12`, é a referência anterior à reorganização.
A [execução registrada no GitHub](https://github.com/portelaariel/CoMAS/actions/runs/43246866789)
aprovou 794 testes, a suíte de falhas 18/18 e o smoke test de implantação.

O [inventário da referência](docs/reference-baseline.json) conserva o commit,
a árvore Git, os hashes dos arquivos versionados e a evidência da CI. Ele não
contém os datasets, os resultados ignorados pelo Git ou o estado dos containers.
Cada experimento congelado continua exigindo sua própria versão e seus próprios
artefatos, conforme o guia de reprodutibilidade.

A tag registra uma referência de software para comparação; não promove a linha
de SLA nem estabelece prontidão de produção.
