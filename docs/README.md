# Documentação do CoMAS

O [README da raiz](../README.md) apresenta o projeto e o estado dos componentes.
Os comandos dos guias são executados a partir da raiz do repositório.

| Tarefa | Leitura recomendada |
| --- | --- |
| Primeiro acesso | [Guia inicial](getting-started.md) |
| Entender o framework | [Arquitetura](architecture.md) |
| Instalar e executar o testbed | [Manual operacional](operations.md#requisitos-e-preparação) |
| Executar um benchmark | [Benchmark automatizado](operations.md#benchmark-automatizado) |
| Entender detecção e coordenação | [Detecção](operations.md#como-a-detecção-funciona) e [decisão entre domínios](operations.md#como-a-decisão-multi-domínio-funciona) |
| Consultar endpoints e defaults | [API](operations.md#api-rest) e [configuração](operations.md#configuração) |
| Reproduzir uma campanha | [Reprodutibilidade](reproducibility.md) |
| Desenvolver o pipeline de SLA | [Protocolos e histórico de SLA](../PREDICTIVE_SLA.md) |
| Auditar um experimento concluído | [Auditor](../llm_auditor/README.md) e [narrativas suplementares](../llm_auditor/AGENT_EXPLANATION.md) |
| Diagnosticar o ETCD do laboratório | [Recuperação e observação](../scripts/README_etcd2_recovery.md) |
| Contribuir ou reorganizar código | [Contribuição](../CONTRIBUTING.md) e [plano incremental](refactoring-plan.md) |

## Documentos e evidências

O manual operacional descreve o uso do sistema. `PREDICTIVE_SLA.md` preserva a
sequência de protocolos de pesquisa, incluindo resultados reprovados e análises
posteriores; use o índice desse arquivo para localizar uma fase específica.

O [inventário da referência](reference-baseline.json) descreve arquivos
versionados no commit anterior à reorganização. Os recibos de execução, CSVs,
timelines e relatórios reais permanecem nos diretórios de cada experimento e
devem ser preservados separadamente.

## Continuidade dos caminhos

O README extenso foi preservado em [operations.md](operations.md). Os scripts,
modelos, configurações e contratos experimentais continuam em seus caminhos
originais nesta primeira etapa. Consulte a [política de reprodução](reproducibility.md)
antes de mudar arquivos usados por protocolos que verificam hashes do código.
