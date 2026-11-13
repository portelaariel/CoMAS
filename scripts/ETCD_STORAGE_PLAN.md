# Plano controlado de persistência e logging do ETCD

Elaboração: 21/10/2026. Revisão para publicação: 12/11/2026.
Estado: **PLANEJADO — NÃO EXECUTADO; DESTINO SEPARADO INDISPONÍVEL**.

Atualização posterior ao inventário: o usuário informou que a administração
**não permite disponibilizar armazenamento separado**. A escolha inicial da Rota A
ficou, portanto, inviabilizada sob a restrição atual. As etapas de migração abaixo
permanecem como plano condicional, não como próxima intervenção autorizada.
Foi recomendada como alternativa a redução de publicações redundantes de estado
e topologia e do logging repetitivo, preservando propostas, claims, validade
temporal e publicação atômica. Essas otimizações **não foram implementadas por
este documento**, não garantem deadline e exigem avaliação/testes próprios antes
de qualquer mudança no runtime. Nenhuma atualização de software decorre apenas
da publicação deste plano no GitHub.

Este documento não autoriza uma intervenção. Nesta fase foram feitas apenas
análise e preparação local: nenhum snapshot novo, arquivo remoto, container,
mount, membro, parâmetro ou experimento foi criado/alterado por este plano.

## 1. Objetivo e fronteiras

Separar a investigação de latência da migração de persistência. Primeiro
decidir o armazenamento de destino; depois preservar fontes e substituir um
runtime por vez, mantendo os membros lógicos e o quorum. A mudança deve ser
reversível sem apagar evidências ou rebobinar o estado do cluster.

Continuam fora de escopo: alterar modelos/políticas de SLA, habilitar autoridade,
atuação ou LLM, elevar o timeout shadow de 1 s, mudar fsync/heartbeat/eleição,
fazer benchmark de escrita, atualizar ETCD ou declarar promoção/deadline cumprido.
A validação científica v4 continua `NOT_PASSED`; deadline permanece `UNKNOWN`.

## 2. Baseline conhecido — revalidar antes da execução

| Membro lógico | ID preservado | IP peer | Runtime observado |
| --- | --- | --- | --- |
| etcd1 | `e08ab541087f7f86` | `192.168.253.11` | original ativo, líder na observação |
| etcd2 | `564101fcba11e661` | `192.168.253.12` | `comas-etcd2-recovered-6a96b2b70d79` ativo |
| etcd3 | `8af88e5f5d1326ea` | `192.168.253.13` | original ativo, follower na observação |

- O container **original `etcd2` deve permanecer parado**, enquanto houver
  replacement para esse membro. A recuperação já concluída não será refeita.
- Imagem local fixada: `sha256:5ba82b3375ad86a21285153085c566ea6dcc58f423e41d5a520c06353eea34c2`;
  ETCD 3.5.16. Não usar tag flutuante nem baixar outra imagem.
- Em etcd1/etcd3, arquivos abertos provaram o caminho real
  `/bitnami/etcd/data/member/{snap,wal}`, sem mount, em overlay2. A variável
  `ETCD_DATA_DIR=/etcd-data` **não** corresponde ao diretório efetivamente usado.
- No membro recuperado, `/comas-etcd-data` é bind mount de
  `etcd2-recovery-mqtix0lz/live-data`; preservar esse diretório integralmente.
- Os três usam ext4 `dm-0` da raiz, sobre `vda3 → vda`, no mesmo guest KVM.
  Logs, Docker e experimentos compartilham esse armazenamento. Três containers
  nessa VM não representam três domínios físicos independentes de falha.
- Inventário às 10:06 UTC: raiz 67% utilizada, aproximadamente 24,39 GiB livres;
  inodes 13%. Logs atuais de etcd1/etcd3: 2,00/4,06 GB. Não houve leitura completa
  desses arquivos nem atribuição de causalidade a partir apenas de seu tamanho.

Evidências: tentativa `qos-online-shadow-v2-diagnostics-ramp-instrumented-20261021T094122Z`,
run shadow `29fa46fe11fc48c2a80b3f06265c37ad`; inventário somente leitura
`storage-inventory.json`, SHA256
`c66015d7d892daab87321d39cc047dc1107e01e6b4a82ad4554dc6d04ca5eef5`.
São observações datadas, não substituem um preflight novo.

## 3. Escolha inicial de armazenamento — bloqueada pela restrição administrativa

Em 21/10/2026, o usuário informou: **"Posso disponibilizar armazenamento separado"**.
A escolha de planejamento é a **Rota A**. Isso confirma a possibilidade de
disponibilizar o recurso, não que ele já esteja anexado/montado, que seus dados
possam ser apagados ou que exista autorização para formatar/migrar. Dispositivo,
filesystem, mount, capacidade e backing ainda precisam ser identificados.
Essa manifestação inicial foi posteriormente substituída pela informação de que
a administração não permite fornecer o recurso; prevalece o bloqueio descrito
no início deste documento.

Uma consulta posterior somente leitura (`lsblk` e `findmnt`) confirmou que a VM
ainda expõe apenas `vda`, de 80 GiB, além de dispositivos loop; nos tipos de
filesystem consultados, somente raiz e `/boot` estavam montados. Nenhum novo
disco de destino foi identificado. **Não executar a Rota A sem mudança autorizada
da restrição e confirmação do destino**;
não selecionar partições de `vda` nem tratar a escolha da Rota A como disponibilidade
efetiva do recurso.

**Rota A, preferida para investigar desempenho:** armazenamento de baixa latência
com I/O separado de `vda`, com backing/limites confirmados pela administração.
SSD é uma preferência técnica, não uma garantia. Um novo disco virtual pode
continuar no mesmo backend físico ou sob a mesma cota de I/O; confirmar isso.

**Rota B, alternativa não escolhida:** persistência explícita e logging limitado
no mesmo `vda`. Tratar como melhoria de gestão/durabilidade operacional, **não**
como correção comprovada da latência. O etcd2 recuperado já está em bind mount e
também apresentou fsync lento. Outro diretório, partição, volume Docker ou LV no
mesmo disco não cria isolamento de I/O físico.

Antes de escolher paths, obter: disponibilidade do destino, backing conhecido,
capacidade livre, permissões, suporte de filesystem, cota/limites de I/O e política
de backup. Não inventar `/srv/etcd` nem criar um volume e chamá-lo de dedicado.
Formatação, particionamento ou montagem de disco exigem um plano/autorização
separados; não fazem parte da substituição automática de runtime.

## 4. Fases e condições de avanço

### P0 — preparar e congelar a intervenção

1. Detalhar a Rota A escolhida: identificar o armazenamento disponibilizado,
   registrar destino/backing e limitações. Ainda não há path/mount aprovado,
   nem ferramenta de migração autorizada para `etcd1`/`etcd3`.
2. Definir janela sem pilotos concorrentes. Manter CoMAS em shadow, sem atuação;
   não parar coletores ou outros serviços implicitamente. Registrar tráfego de
   fundo e sua eventual mudança como parte da intervenção.
3. Capturar inventário atualizado: membros/cluster ID, IDs e inícios dos runtimes,
   imagem, configuração efetiva, rede/aliases/IPs/bindings, diretórios reais e mounts,
   UID/GID/modos e espaço necessário para todas as cópias/arquivos de preservação.
4. Validar os três membros ativos, mesmo cluster/membership, liderança estável,
   ausência de alarmes e leituras linearizáveis em todos. Exigir os dois futuros
   sobreviventes saudáveis antes de parar qualquer alvo. Se já houver degradação,
   **não iniciar uma segunda indisponibilidade**.
5. Definir antes de aplicar: timeout operacional de cada fase, condições de
   interrupção, responsáveis, coleta de recibos e mecanismo de fencing que
   impeça dois processos com o mesmo member ID.

### P1 — preservar, com autorização específica

- Fazer snapshot novo do cluster e verificar integridade com a ferramenta 3.5.16
  fixada, em destino novo. Registrar revisão/hash/data e teste offline conforme
  procedimento próprio. A preservação antiga continua intocada, mas não prova que
  os dados mais recentes estão salvos. Backup também consome I/O: não concorrê-lo
  com piloto ou mudança de membro.
- Snapshot restaurado é material de recuperação de desastre/teste offline,
  **não seed de um membro que deve manter sua identidade no cluster existente**.
  Não restaurar o snapshot por cima do diretório ativo.
- Preservar containers originais, seus logs e metadados. Não usar `docker rm`,
  `prune`, truncate ou logrotate externo sobre arquivos do driver JSON.
  Arquivos de log ativos não são cópias imutáveis; arquivar/verificar versões
  coerentes quando o runtime afetado estiver parado, sem prometer um hash estável
  de arquivo que ainda cresce. Não obrigar uma varredura multi-GB em 20 s.
- Dimensionar cópias de dados completos, WAL, seed, probe, live, logs arquivados e
  margem operacional. Recusar a fase se não couber; não assumir que 24 GiB bastam
  para qualquer política de arquivamento. Não apagar fontes para abrir espaço.

### P2 — primeiro membro: etcd3, somente se ainda follower

Se a liderança/identidade mudou, parar e rever a ordem; não transferir liderança
silenciosamente. O etcd2 recuperado permanece intocado nesta etapa.

1. Revalidar os sobreviventes `etcd1` e o runtime recuperado do `etcd2`; registrar
   o último estado/revisão/índice observados e o quorum de 2/3 esperado durante
   a manutenção. Não executar `member remove/add`: é migração de runtime/dados
   do **mesmo** membro, não substituição de identidade.
2. Após autorização para esta parada, parar **somente o runtime alvo etcd3**.
   Confirmar processo encerrado e ausência de escritor no diretório fonte.
   Não remover o container, WAL, logs ou desconectar endpoints alheios.
3. Copiar de forma coerente o diretório completo real de etcd3, incluindo WAL e
   snapshots, a partir do alvo parado, para um seed novo. Preservar os metadados
   originais em arquivo e registrar hashes. Não copiar banco/WAL vivo nem copiar
   os dados de outro membro como se fossem desse ID. Rejeitar arquivos/path
   inesperados e validar ownership/permissões do destino.
4. Preparar probe sem rede, sobre uma **cópia** do seed. Exigir carregamento do
   WAL com member ID/cluster ID esperados, versão correta e ausência de fresh
   bootstrap, force-new-cluster, fatal ou corrupção. Um probe isolado não tem
   quorum e não constitui teste de disponibilidade online.
5. Descartar o probe como fonte de produção: mantê-lo parado para evidência e
   criar a cópia live a partir do seed imutável, nunca de arquivos modificados
   pelo probe. Não executar dois probes/runtimes sobre o mesmo live-data.
6. Criar um replacement com nome/rótulo de intervenção exclusivos, imagem
   fixada, data-dir/bind explícitos e política inicial `restart=no`. Preservar
   member ID, nome lógico, peer/client URLs, aliases e port bindings efetivos.
   Usar a semântica de reinício do membro existente, não bootstrap de cluster.
   A entrada direta do binário e todas as flags devem ser revisadas; não depender
   de variáveis que o bootstrap Bitnami possa sobrescrever.
7. Confirmar que IP/portas estão livres **sem remover o seu ocupante por reflexo**.
   Iniciar somente o replacement autorizado. Revalidar o cluster e exigir catch-up
   em relação ao índice registrado, leituras linearizáveis pelo endpoint novo e
   a partir de um sobrevivente, membership inalterado e três observações
   consecutivas estáveis. Índices/revisões podem avançar; não exigir igualdade de
   contadores capturados em instantes diferentes.
8. Arquivar recibo com fontes, imagem, opções, IDs, timestamps, resultados e
   processos próprios. Só avançar ao próximo membro depois de restabelecer 3/3
   e de confirmar que o original etcd3 ficou parado e cercado contra partida dupla.

Essa ferramenta ainda precisa ser implementada e testada para migração do alvo.
O helper `recover_etcd2_member.py` é específico de etcd2 e **não deve ser executado
com substituição textual de nomes/IDs**.

### P3 — segundo membro: etcd1

Repetir as mesmas garantias somente depois de P2 concluída e autorização própria.
Se etcd1 continuar líder, apresentar explicitamente a opção de transferência
controlada de liderança para um membro saudável; ela não é uma operação somente
leitura e não está autorizada por este documento. Alternativamente, um restart
do líder implica eleição e possível interrupção breve, que precisa ser aceita.

Não migrar etcd1 enquanto etcd3 ainda estiver indisponível. A liderança/termo
podem mudar legitimamente numa intervenção aprovada; registrar o evento, mas
exigir estabilidade em cada série de verificação, não o termo histórico 9 para
sempre. Migração posterior do bind do etcd2 para outro disco é outra etapa,
após os outros dois estarem saudáveis; nunca ativar seu container original.

## 5. Logging dos runtimes novos

Proposta inicial, a dimensionar e congelar antes da criação: driver `json-file`,
`max-size=20m`, `max-file=5` **por replacement**, com nível de log existente.
Isso dá um orçamento aproximado de 100 MiB por runtime, não retenção temporal
garantida. Medir/considerar a taxa de log e garantir a preservação das janelas
experimentais antes que a rotação descarte arquivos novos antigos.

Não editar `daemon.json` nem reiniciar o Docker para aplicar a proposta. Não
recriar controladores/coletores como efeito colateral. Os logs históricos nos
originais ficam preservados; a rotação do replacement não deve destruí-los.
Configurar um default global não atualiza os containers existentes.

## 6. Interrupção, fencing e rollback

| Situação | Ação prevista, sujeita à autorização da fase |
| --- | --- |
| Antes de parar o alvo | Abortar sem mudar runtimes; manter plano/evidências |
| Alvo parado, sem replacement conectado ao cluster | Se os dois sobreviventes continuam saudáveis, revalidar fonte e IP/portas e considerar reiniciar só o alvo original; nenhum membro pode estar duplicado |
| Replacement já conectado/possivelmente gravou | Parar o avanço; preservar seus dados mais recentes, seed e originais. Não iniciar automaticamente o original com WAL antigo nem fazer restore do snapshot |
| Perda de um sobrevivente ou quorum | Interromper imediatamente a sequência; não parar o segundo membro, não remover membership nem tentar force-new-cluster |
| Corrupção, identidade divergente, bind/endpoint ocupado | Não iniciar/reiniciar às cegas; fencing do replacement próprio e revisão manual |

Após o replacement participar, rollback significa recuperar configuração/runtime
com um estado coerente adequado ao cluster atual, **não rebobinar o banco**. Um
backup/seed anterior pode estar atrasado. A decisão exige inspeção dos últimos
WALs/estado dos sobreviventes e um procedimento específico; a ferramenta não
deverá improvisá-la nem apagar dados. Se restarem dois membros saudáveis, manter
essa disponibilidade degradada e parar a intervenção é preferível a uma segunda
ação não validada. Registrar estado `HOLD/REVIEW_REQUIRED`, sem tratar isso como
migração ou rollback concluído.

## 7. Verificação pós-migração e compatibilidade da auditoria

- Revalidar dados/identidades, quorum, alarmes, observações de leitura e configurações
  efetivas de mounts/logging. Comparação por hash KV, se necessária, deve usar uma
  mesma revisão acordada e operação limitada; não confundir hash de arquivos WAL
  com igualdade lógica de banco em execução.
- Os helpers/recibos atuais congelaram etcd1/etcd3 **originais ativos**. Uma
  migração legítima fará essas guardas recusarem o novo layout. Criar uma baseline
  de migração aprovada, com linhagem para os recibos anteriores e validadores
  específicos. Não reescrever recibos históricos nem desabilitar guardas para
  forçar `PASS`; não alterar os helpers SHA256-pinned já usados.
- Avaliar persistência sob carga apenas numa campanha nova, autorizada e definida
  antes de executar. Capturar fsync/commit por deltas de histogramas, pressão I/O,
  gaps/falhas e overhead. Ausência de operações no intervalo é **não avaliado**,
  não latência zero. Médias históricas acumuladas não demonstram cauda/P99.
- As recomendações ETCD sobre latências de persistência são referências
  diagnósticas, não um gate científico aprovado deste projeto. Congelar limiares,
  volume mínimo de observações e workload antes da comparação. Não reutilizar
  apenas sucessos nem excluir as tentativas interrompidas anteriores.
- Uma migração bem-sucedida não prova antecipação SLA, eficácia preventiva,
  escalabilidade ou participação decisória da LLM.

## 8. Bloqueios e próxima autorização

Para tornar a etapa P2 executável ainda faltam:

1. Identificação/provisionamento do armazenamento separado escolhido: backing,
   dispositivo, filesystem, caminho/mount, capacidade e permissões efetivos
   aprovados. Não confundir possibilidade de disponibilizar com recurso já pronto.
2. Ferramenta de migração específica, testes offline de falha/fencing/rollback,
   parâmetros congelados e política de logs dimensionada.
3. Autorização explícita para snapshot/preservação, parada e substituição de
   **um único membro**. Nenhum `--apply` deve ser fornecido antes desses gates.

**Não executar `eMSN_ENV/setup_env.sh` como migração:** a implementação observada
remove os containers `etcd*` e inicia outro cluster com `initial-cluster-state=new`.
Não usar o setup geral, prune, mudança de membership, defrag/compactação, limpeza
de logs ou elevação de timeout como atalho para este plano.

## Referências

- [ETCD: manutenção sequencial e requisitos de quorum](https://etcd.io/docs/v3.5/op-guide/runtime-configuration/).
- [ETCD: restore de snapshot altera identidades](https://etcd.io/docs/v3.5/op-guide/recovery/#restoring-from-snapshot).
- [ETCD: sensibilidade à latência de disco e contenção](https://etcd.io/docs/v3.5/op-guide/hardware/).
- [Docker: configuração e defaults do driver JSON](https://docs.docker.com/engine/logging/drivers/json-file/).
- [Docker: persistência de dados write-heavy](https://docs.docker.com/engine/storage/drivers/select-storage-driver/).

Este plano é preparatório: não contém comandos executáveis de parada, criação,
formatação, restauração ou alteração de membership.
