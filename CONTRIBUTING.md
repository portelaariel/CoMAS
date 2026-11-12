# Contribuir com o CoMAS

Comece pelo [mapa da arquitetura](docs/architecture.md) e pelo
[plano incremental](docs/refactoring-plan.md). O repositório combina serviços do
testbed com código de pesquisa; identifique qual caminho a mudança afeta.

## Branches e revisões

Use uma branch `codex/<assunto>` por mudança coesa. Confirme a base do trabalho:
enquanto uma evolução estiver em revisão, `main` pode não conter os módulos
mais recentes. Um PR empilhado deve indicar qual PR ou branch precisa ser
integrado antes dele.

Antes de mudar de versão em um checkout existente:

```bash
git status --short
git log -1 --oneline
git worktree list
```

Preserve alterações locais e resultados. Prefira outro worktree quando um
experimento depender da versão em uso. A [referência de reorganização](docs/reproducibility.md)
explica a diferença entre uma baseline geral e o commit de um protocolo antigo.

## Escopo de uma mudança

Descreva o problema, o comportamento resultante e como foi verificado. Separe
reorganização de código de mudanças em thresholds, modelos, regras, schemas,
modos de atuação ou critérios experimentais. Isso permite avaliar equivalência
sem misturar uma refatoração com um novo método.

Os contratos e campanhas registram hashes de arquivos. Não reformate, mova ou
substitua arquivos históricos sem tratar a reprodução da versão correspondente.
O [guia de reprodutibilidade](docs/reproducibility.md) descreve essa fronteira.

## Verificação

Para a verificação completa, na raiz:

```bash
bash scripts/validate_repository.sh
```

A suíte inclui testes sem infraestrutura externa, reprodução de fixtures,
falhas determinísticas e smoke test do formato de implantação. Os testes usam
Python da máquina; a referência foi verificada na CI com Python 3.13, enquanto
a imagem atual do preditor usa Python 3.9.

Durante uma mudança de código, execute primeiro os testes relevantes e depois
as verificações exigidas para a integração. Para documentação, confira links,
comandos, exemplos e o diff; não altere os resultados congelados para fazer
uma verificação passar. A CI continua executando a suíte completa nos PRs.

Executar setup, benchmark ou recuperação no servidor é uma operação distinta
de testar o código. Esses comandos podem modificar recursos do laboratório e
precisam respeitar o estado dos experimentos em andamento.

## Artefatos e código de terceiros

Datasets, resultados de campanha, snapshots ETCD, logs e backups devem ser
preservados nos locais definidos pelos protocolos, fora dos commits de código.
Revise os caminhos staged explicitamente; evite adicionar em massa arquivos de
uma pasta de trabalho com saídas locais.

Preserve avisos de autoria e licença dos componentes de terceiros. Antes de
remover arquivos de `rest_client/` ou `ryu_apps/`, confira os imports, os contextos
de build e as dependências do serviço correspondente.
