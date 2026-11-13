# Reprodutibilidade e versões de referência

## Referência anterior à reorganização

| Campo | Valor |
| --- | --- |
| Commit | `40b60906dfa299309fd423022bb00225666d7ff6` |
| Tag | `baseline/pre-refactor-2026-11-12` |
| CI | [Repository validation — execução 43246866789](https://github.com/portelaariel/CoMAS/actions/runs/43246866789) |
| Resultado de software | 794 testes; suíte de falhas 18/18; smoke test de implantação aprovado. |
| Inventário | [reference-baseline.json](reference-baseline.json) |

O inventário usa os bytes dos blobs Git desse commit, e não arquivos de um
diretório de trabalho possivelmente modificado. Ele registra SHA256 e IDs dos
blobs para os arquivos versionados. O próprio inventário é posterior à referência
e não está incluído nela.

Essa referência não contém o estado dos containers, imagens completas, volumes
ETCD, CSVs externos, resultados ignorados pelo Git ou credenciais. Uma imagem
declarada por nome em um Dockerfile também não é um snapshot imutável de toda a
infraestrutura. Reproduzir um resultado de rede exige preservar esses elementos
conforme o protocolo específico.

## Preservar a versão de cada experimento

Os módulos de campanhas usam listas `CODE_FILES`, hashes e validações de
linhagem. Por exemplo, `predictive_sla_shadow_v2.py` inclui o código da versão
anterior no seu inventário e verifica os hashes ao carregar a configuração.
Diversos protocolos também fixam políticas, modelos, diretórios e nomes de
saída.

Por isso, mover um módulo, transformar um script antigo em um wrapper ou
formatar um arquivo protegido pode invalidar uma configuração existente mesmo
quando a intenção é manter o comportamento.

Para um experimento já congelado:

1. Identifique o commit, os arquivos e os hashes registrados pelo próprio
   protocolo. A tag geral de reorganização não substitui essa versão.
2. Preserve os artefatos originais e os caminhos exigidos pelo carregador.
   Alguns manifestos contêm caminhos absolutos; copiá-los para outra pasta não
   constitui uma migração válida por si só.
3. Use um checkout separado da versão registrada. Não edite JSONs nem recalcule
   hashes para fazer uma versão diferente parecer a original.
4. Grave análises novas em saídas novas, conforme o contrato da ferramenta.
   Preserve resultados reprovados, timeouts e fontes incompletas.

Um worktree permite separar o código sem trocar o checkout em uso:

```bash
git worktree list
git worktree add --detach ../CoMAS-reference baseline/pre-refactor-2026-11-12
```

Esse comando cria apenas outro checkout de código; ele não copia resultados,
volumes, imagens ou a infraestrutura do experimento.

## Primeira etapa da reorganização

Na primeira etapa documental, os arquivos de runtime, contratos, modelos, fixtures,
scripts e configurações foram mantidos nos caminhos existentes. O manual longo do README foi
preservado em `docs/operations.md`, com navegação e orientações de versão
atualizadas. `PREDICTIVE_SLA.md` continua no caminho original.

O inventário permite conferir o que mudou desde a referência. Uma comparação
deve separar mudanças documentais das mudanças de código; a identidade dos
arquivos da referência não deve ser apresentada como identidade de todas as
versões futuras.

## Primeira extração das primitivas de tráfego

O runtime passa a importar Holt e o detector de resíduos dos pacotes
`comas.forecasting` e `comas.detection`. O conteúdo de `SeriesState` e da
orquestração permanece preservado; o Dockerfile inclui o novo pacote. Os
contratos e as transformações de `offline_model.py` continuam os mesmos.

`tests/fixtures/runtime_primitives_baseline_v1.json` registra saídas obtidas das
classes originais no commit da referência antes da extração: três sequências
Holt e quatro sequências do detector. O teste verifica estado, previsões,
resíduos, warmup, janela MAD, limites assimétricos e adaptação opcional. Outro
teste monta o layout declarado pelos comandos COPY do Dockerfile e verifica
os imports em um processo sem dependências do serviço.

Esses testes são regressões de comportamento, não validação independente do
método. A verificação adicional da imagem real está descrita abaixo. O caminho
multi-horizonte de SLA e seus protocolos permanecem nos módulos anteriores. A fonte integral do runtime
antigo continua disponível pela tag da referência; o inventário não é refeito
para apresentar os arquivos novos como se fossem os originais.

## Histórico CSV, cache de resíduos e imagem real

O exportador foi extraído para `comas.telemetry` com o corpo da classe original
preservado. O registro repetido de inatividade e priming foi reunido em um método
de `SeriesState`, mantendo a ordem histórico → CSV e os campos sem pontuação.
Testes cobrem formato, anexação, falhas de I/O e opções alteradas pela API.

A otimização do detector evita ordenar novamente uma janela MAD estável. A
sequência de pontuação continua a mesma; testes adicionais comparam edições
externas da janela, troca de fator, adaptação, calibração fixa e subclasses.
As fixtures da referência não foram regeneradas.

Foram construídas localmente a imagem da primeira extração (`335442f`) e a
imagem com histórico/cache refatorados, usando a mesma base Python 3.9 e o mesmo
smoke test. Relógio e UUIDs foram fixados, e o fuso foi UTC. Para o cenário de
dois fluxos, com priming, anomalia, supressão repetida, inatividade e mudança de
configuração, as respostas de seis endpoints e os dois CSVs ficaram idênticos.
O SHA256 do payload comparado foi
`c2fa6354a8a0a1dda886ad06648d1dd3169bd9b67f9bf0f2444c138b5f637094`.
Esse hash documenta a comparação local na mesma plataforma; não é imposto como
resultado universal entre arquiteturas.

O procedimento atual pode ser executado com:

```bash
docker build --tag comas-runtime-check --file Dockerfile.flow_predictor .
bash scripts/test_runtime_image.sh comas-runtime-check
```

O script usa o serviço real via cliente de testes Flask em um container sem
rede, com raiz somente leitura e arquivos temporários em memória. Não inicia
o coletor. Isso verifica empacotamento, API e persistência controlada; não testa
o plano de dados do laboratório nem substitui uma campanha de rede. A CI também
constrói e verifica essa imagem em um job separado.

`experiments/benchmark_residual_scoring.py` compara o detector atual com uma
referência Git explícita e verifica saídas antes de medir. Uma execução local
Python 3.9/ARM64, com janela 120 e mediana de cinco repetições de 30 mil chamadas,
mediu aproximadamente 5,5× no caso de anomalias rejeitadas consecutivas e 3,3×
para resíduos normais constantes. Resíduos variáveis e calibração fixa ficaram
próximos do original (razões de tempo de aproximadamente 1,00 e 0,97). Esses
resultados descrevem os casos do microbenchmark, sujeitos a ruído de medição;
não são ganhos de latência global, de inferência LLM ou de qualidade de detecção.

## Critérios para extrair módulos no futuro

Cada extração precisa de uma comparação adequada à responsabilidade alterada:

| Área | Evidência de equivalência esperada |
| --- | --- |
| Previsão | Mesma sequência de entradas, estados, previsões e tratamento de resets/lacunas. |
| Detecção | Mesmos resíduos, classificações e deduplicação de eventos. |
| Agentes | Mesmas propostas e decisões para tempo, modelo, topologia e quórum equivalentes. |
| Autoridade | Mesmas autorizações, recusas e condições de claim; nenhuma nova ligação de atuação implícita. |
| Auditoria | Mesmos vereditos, referências e contratos para os mesmos artefatos. |
| Reprodução histórica | Carregadores e hashes originais ainda utilizáveis no checkout correspondente. |

As comparações usam timestamps e identidades controlados quando necessário;
igualdade de mensagens contendo horários ou UUIDs novos não é uma medida útil
de equivalência por si só.

## Interpretação dos resultados

CI aprovada demonstra o resultado das verificações de software executadas.
`COMPLETED` descreve a conclusão de uma execução; `ACCEPTED_STRUCTURALLY` descreve
um contrato de saída aceito. Esses estados não substituem critérios científicos
ou operacionais. A campanha prospectiva v4 permanece `NOT_PASSED`, e a viabilidade
de prazo preventivo continua exigindo evidência própria.
