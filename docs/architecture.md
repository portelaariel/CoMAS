# Arquitetura atual

Este mapa parte da referência `40b60906dfa299309fd423022bb00225666d7ff6` e
identifica as extrações de primitivas e histórico para `comas/`. As próximas
fronteiras estão descritas no [plano incremental](refactoring-plan.md).

## Serviços do testbed

Na configuração usual, dois domínios têm uma instância Ryu, um serviço
SimpleSwitch, um preditor CoMAS e um FlowBlocker por domínio. Mininet e OVS
implementam o plano de dados. Três membros ETCD replicam o estado compartilhado.

```mermaid
flowchart LR
    OVS["Mininet / OVS"] --> RYU["Ryu: contadores e eventos"]
    RYU --> COL["CoMAS: coleta e previsão"]
    COL --> DET["Detecção e evidência local"]
    DET --> MCDA["MCDA observacional"]
    DET --> AGENT["Agente determinístico por domínio"]
    AGENT <--> STORE[("ETCD: propostas, evidências e claims")]
    AGENT --> GATE["Gate de autoridade e claim"]
    GATE --> LIVE["Verificações do modo authority-live"]
    LIVE --> FB["FlowBlocker"]
    FB --> OVS
```

O desenho destaca a atuação autoritativa dos agentes. O runtime também conserva
o caminho local/MCDA conforme a configuração. A seleção de modo define qual
caminho pode atuar; em `authority-live`, o MCDA permanece comparador.

## Responsabilidades físicas atuais

| Área | Implementação principal | Responsabilidade |
| --- | --- | --- |
| Composição do runtime | `flow_predictor_cnsm.py` | Lê configuração, instancia engine/coletor e expõe a API Flask. |
| Previsão de tráfego | `comas/forecasting/holt.py`, `offline_model.py`; `SeriesState` no runtime | Mantém o estado Holt e usa as transformações do contrato offline existente. |
| Detecção por resíduos | `comas/detection/residual.py`; `SeriesState` no runtime | Avalia resíduos com warmup, MAD, calibração fixa e limiares assimétricos. |
| Coleta e histórico | `Collector` no runtime; `comas/telemetry/history.py`; `qos_telemetry.py` | Converte contadores, preserva qualidade das amostras e exporta históricos. |
| MCDA | `collaborative_decision.py`; `CollaborativeDecisionManager` | Combina evidências e registra a decisão multicritério. |
| Propostas e deliberação | `agent_protocol.py`, `domain_agent.py`; `AgenticShadowManager` | Valida propostas e avalia a compatibilidade/quórum entre domínios. |
| Autoridade | `agent_authority.py`; verificações adicionais no runtime | Revalida a decisão e oferece o claim atômico. O módulo isolado não chama o FlowBlocker. |
| Encaminhamento e atuação | `rest_client/`, `ryu_apps/`, `flow_blocker/` | Instala encaminhamento e converte pedidos autorizados em políticas OpenFlow. |
| API | Rotas `/predictor/*` no runtime | Expõe status, modelo, previsões, evidências, feedback e configuração. |

Os diretórios de serviços incluem código de terceiros com avisos próprios.
Uma limpeza futura deve verificar uso e origem antes de remover ou substituir
esses arquivos.

`flow_predictor_cnsm.py` importa e continua expondo os nomes `HoltPredictor` e
`ResidualAnomalyDetector` e `PredictionHistoryExporter`. As classes também podem
ser importadas por `comas.forecasting`, `comas.detection` e `comas.telemetry`,
sem Flask, ETCD, leitura de modelo, configuração de ambiente ou criação de
threads. O exportador só abre arquivos quando construído e usado explicitamente.
`SeriesState`, configuração, coleta, coordenação, feedback e rotas permanecem
no serviço nesta extração.

`SeriesState._record_unscored_sample` concentra o registro antes repetido nos
caminhos de inatividade e priming: acrescenta a amostra ao histórico e depois
exporta resíduo zero e z-score ausente. As opções atualizadas pela API continuam
sendo consultadas pelas séries já existentes.

O detector adaptativo reaproveita mediana/MAD quando a janela permanece
inalterada. O cache é limitado a uma janela de números imutáveis e valida as
identidades dos elementos e o fator MAD antes de reutilizar o resultado. Uma
janela alterada volta ao cálculo original; a calibração fixa mantém seu caminho
direto. A pontuação, os limiares e a exclusão de resíduos anômalos são preservados.

O pacote `comas/` fica na raiz para funcionar com a execução e o contexto Docker
atuais, sem ajustes de `PYTHONPATH` ou instalação de pacote. O Dockerfile copia
esse diretório para `/app/comas/`. As transformações matemáticas continuam no
módulo puro `offline_model.py`, compartilhado com o treino existente.

Previsores parecidos não são necessariamente intercambiáveis. O caminho de
tráfego prevê antes de atualizar o estado e pode excluir atualizações anômalas.
Os previsores QoS têm contratos multi-horizonte e arredondamentos próprios.
Também há diferenças entre a mediana superior do detector e a mediana usada por
rotinas de treinamento. Unificar essas implementações sem tratar os contratos
mudaria o método e os resultados históricos.

## Consenso de domínio e consenso do armazenamento

O acordo dos agentes exige propostas compatíveis para o fluxo, modelo, tempo
e topologia relevantes. `AGREED` é um estado deliberativo; a autorização e o
claim são etapas posteriores.

Os três membros ETCD usam Raft para replicar o armazenamento. A maioria de dois
membros de um cluster de três é uma propriedade dessa camada. Esses membros
não são três votos de domínio nem tornam uma proposta incompatível aceitável.

## Linha experimental de SLA

```mermaid
flowchart LR
    PORT["Contadores de portas"] --> QOS["qos_telemetry: qualidade e utilização"]
    QOS --> DATA["CSV por domínio"]
    DATA --> FIT["Treino e calibração offline"]
    FIT --> MODEL["Modelo multi-horizonte congelado"]
    MODEL --> FORECAST["Previsões por horizonte"]
    QOS --> FORECAST
    FORECAST --> RISK["Risco e persistência / entrada preventiva"]
    RISK --> PAIR["Risco + proposta em transação experimental"]
    PAIR --> SHADOW["Avaliação de acordo em shadow"]
    DATA --> EVAL["Backtests e avaliação de episódios"]
    SHADOW --> JOURNAL["Jornais e análise temporal"]
```

`qos_holt.py` e `qos_damped_holt.py` representam modelos e previsores.
`sla_risk.py`, `sla_episode_evaluation.py` e os avaliadores de campanhas
definem risco, persistência, episódios observados e correspondência de avisos.
Os módulos `predictive_sla_validation*` e `predictive_sla_shadow*` mantêm
protocolos e análises versionados.

A publicação shadow usa namespace ETCD experimental e não entrega uma
autorização ao caminho de atuação. Os scripts do piloto controlam a ligação
entre telemetria, modelo e proposta; não existe um caminho preventivo completo
promovido para produção.

## Auditoria posterior

`llm_auditor/` lê metadados, resumo e timeline de execuções concluídas.
Adaptadores normalizam os eventos, regras determinísticas emitem vereditos e
certificados conservam a ligação com as evidências.

Ollama é opcional para explicações e avaliações experimentais. A aceitação
estrutural de uma saída não constitui verificação independente da verdade da
prosa. Narrativas suplementares continuam exigindo revisão factual.

Não há chamada à LLM no gate de autoridade nem um árbitro LLM implementado para
resolver desacordo dos agentes. Esse é um objetivo futuro que exige contrato,
política, orçamento de tempo e validação próprios.

## Dados e proveniência

- Modelos incluídos em `models/` são artefatos versionados de referência.
- Históricos e campanhas reais ficam fora do código, em diretórios ignorados
  pelo Git como `experiments/results/` e `prediction_history/`.
- Protocolos congelados registram hashes de modelos, dados e arquivos de código;
  alguns também exigem caminhos absolutos e diretórios irmãos específicos.
- Relatórios offline preservam falhas, fontes incompletas e resultados
  desconhecidos. Reorganizar o código não transforma esses estados em sucesso.

Essas dependências são o motivo para separar primeiro documentação e inventário,
antes de alterar a composição dos módulos. O procedimento de comparação está
em [reproducibility.md](reproducibility.md).
