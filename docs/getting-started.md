# Guia inicial

Escolha primeiro entre verificar o código, auditar um experimento existente ou
executar um novo ensaio no laboratório. Esses caminhos têm requisitos e efeitos
diferentes.

## 1. Obter a referência do código

Para uma cópia nova da referência anterior à reorganização:

```bash
git clone https://github.com/portelaariel/CoMAS.git
cd CoMAS
git switch --detach baseline/pre-refactor-2026-11-12
```

Para contribuir, crie uma branch própria a partir da base acordada no PR.
Em um checkout já existente, consulte primeiro `git status --short` e
`git log -1 --oneline`; alterações locais e artefatos experimentais precisam
ser preservados antes de trocar a versão. O [guia de contribuição](../CONTRIBUTING.md)
descreve esse fluxo.

A referência é um ponto de comparação, não uma substituição automática do
commit registrado por cada experimento antigo.

## 2. Verificar o código sem iniciar o laboratório

Na raiz:

```bash
python3 --version
bash scripts/validate_repository.sh
```

O script verifica sintaxe, configuração, validação de argumentos, testes,
falhas determinísticas dos agentes e o formato do deploy. Ele não inicia
containers nem o Mininet. O final esperado inclui testes `OK`,
`agentic_faults: 18/18 passed` e `deploy_smoke: ok`.

A imagem do preditor usa Python 3.9; a CI da referência usa Python 3.13.
Consulte os Dockerfiles para dependências de cada serviço. Esse teste local
não verifica conectividade, desempenho de disco ou comportamento da rede real.

## 3. Auditar um experimento existente

Esse caminho lê artefatos já coletados e não precisa iniciar o testbed.
Substitua o caminho abaixo pelo diretório real da execução:

```bash
RUN_DIR="/caminho/da/execucao"
test -f "$RUN_DIR/timeline.ndjson" || exit 1
python3 -m llm_auditor "$RUN_DIR" --mode audit
```

Confira os arquivos de saída e as regras aplicadas antes de acrescentar uma
explicação por LLM. Modos que usam Ollama, versões dos contratos e proteção
contra sobrescrita estão no [manual do auditor](../llm_auditor/README.md).

O modelo LLM explica evidências registradas. Ele não participa do consenso nem
desbloqueia uma decisão sem quórum no runtime atual.

## 4. Executar o laboratório Linux

Para um ambiente novo, siga, na ordem:

1. [Requisitos e preparação](operations.md#requisitos-e-preparação).
2. [Execução manual em dry-run](operations.md#execução-segura-em-dry-run).
3. [Benchmark automatizado](operations.md#benchmark-automatizado).

Esses procedimentos criam ou removem recursos Docker/Mininet e geram tráfego.
Em um servidor com campanhas ou membros ETCD preservados, confira o estado
existente e a [política de reprodução](reproducibility.md) antes de executar
setup, cleanup ou coleta. Um procedimento de bootstrap não é um procedimento
de recuperação de um cluster existente.

## 5. Trabalhar com previsão de SLA

A sequência implementada é telemetria QoS, previsão multi-horizonte, avaliação
de risco, propostas experimentais e observação do acordo em shadow. Treinamento,
backtests e campanhas prospectivas têm entradas próprias.

Consulte [PREDICTIVE_SLA.md](../PREDICTIVE_SLA.md) para escolher o protocolo e
preservar os limites da versão. A v4 continua `NOT_PASSED`; um piloto posterior
concluído não altera esse resultado. O caminho experimental de SLA não está
conectado a um atuador preventivo autorizado.
