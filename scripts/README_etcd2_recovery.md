# Controlled recovery of the existing laboratory etcd2 member

For the **not-yet-applied** persistence/logging migration of the other members,
see [ETCD_STORAGE_PLAN.md](ETCD_STORAGE_PLAN.md). This recovery helper remains
specific to the original etcd2 incident; do not repurpose its `--apply` for
etcd1/etcd3 or weaken its frozen original-container guards after a migration.

`recover_etcd2_member.py` is **specific to the inspected ETCD 3.5.16 deployment**:

| Member | ID | Peer IP |
| --- | --- | --- |
| etcd1 | `e08ab541087f7f86` | `192.168.253.11` |
| etcd2 | `564101fcba11e661` | `192.168.253.12` |
| etcd3 | `8af88e5f5d1326ea` | `192.168.253.13` |

It is not a generic cluster-recovery utility. The default is a read-only
preflight. Explicit `--apply` is required for any extraction, container creation
or start. Run on the Ubuntu host with Python 3.10+, Docker and cached `sudo -v`.
Only the standard library is used; the script can be transferred independently.

## Required preserved inputs

- Backup root: `containers.json`, `etcd2.log`, and a point-in-time `cluster.db`.
- Export directory within that root: `rootfs.tar` and the four-file `SHA256SUMS`
  created by the preservation procedure. The script does not use the failed
  `/etcd-data` archive.
- Completed offline snapshot-drill directory within the same backup root:
  `helper.json`, the original one-element `docker inspect` JSON array. It must
  show successful exit, network `none`, and a read-only input snapshot mount.

The snapshot and its restored directory are **backup prerequisites only**.
They are never used to seed the recovered member: snapshot restore changes
member/cluster identities. The source of runtime data is exclusively the
original `bitnami/etcd/data` subtree of the preserved filesystem export.

## Read-only preflight

```bash
sudo -v
python3 scripts/recover_etcd2_member.py \
  --backup-root /absolute/path/to/etcd-preservation-XXXXXXXX \
  --export-root /absolute/path/to/etcd-preservation-XXXXXXXX/etcd2-filesystem-XXXXXXXX \
  --restore-test-root /absolute/path/to/etcd-preservation-XXXXXXXX/restore-check-XXXXXXXX
```

Validation covers input hashes, the completed drill, exact original container
IDs/configuration/start times, stopped `etcd2`, no original mounts/automatic
restart, known member IDs and URLs, stable survivor leader/term, linearizable
reads, an unoccupied `.12`, exact port bindings and a locally available image
pinned by ID. Implicit image-level ETCD settings, volumes or healthchecks fail
closed rather than being discarded. At least 512 MiB of `MemAvailable` is
required. No `endpoint health` probe or key-value write is used.
Linearizable probes use an exact-key `get --keys-only --consistency=l` with
JSON output to validate member/cluster headers without fetching values.
ETCD 3.5.16's `--count-only` is not compatible with this JSON output mode.

## Apply after authorization

Append `--apply` to the same command. The script:

1. Creates a unique **sibling** `etcd2-recovery-*` output directory.
2. Extracts only regular original member files. Traversal, duplicate names,
   links and special files are rejected. New copies are private and owned by
   the operator; original archive ownership metadata remains preserved in tar.
3. Starts a copy with `--network=none`. ETCD's own WAL-restart and subsequent
   server-start logs must establish the existing member ID, cluster ID and
   compatible term/commit index. Fresh/forced bootstrap and fatal/panic logs
   are rejected. This is an identity/loading check, **not quorum health**.
   In this ETCD version, the client API waits for quorum-dependent startup and
   is intentionally not used for this isolated check.
4. Stops that probe and creates a fresh copy from the untouched seed, never
   from the probe or the snapshot drill. Revalidates the active cluster.
5. Starts `comas-etcd2-recovered-<id>` on the existing network as `.12`, with
   network alias `etcd2` and the original published ports. The pinned ETCD
   binary runs directly, bypassing the failing Bitnami setup script. It uses
   `--initial-cluster-state=existing`, never `--force-new-cluster`.
6. Requires the existing cluster/member identity, catch-up, matching leader and
   term, unchanged membership, and linearizable reads from all members,
   including a request from `etcd1` to `.12`. Three consecutive successful
   observations are required. Preserved input hashes are checked again.

The original `etcd2` container remains stopped and unchanged. **Do not start it
while the replacement is running.** The recovered runtime uses a persistent
bind-mounted `live-data` directory and `restart=no`: automatic boot/startup
policy is deliberately not changed in this first recovery. Keep the recovery
directory while that runtime is in use.

Failures and interrupts attempt to stop only the newly created, run-labelled
containers. They never remove containers/data, change membership, disconnect
an existing network endpoint, or restart originals. Data, logs and inspect
receipts remain available. SIGKILL/host loss cannot be caught: keep the terminal
open until the final receipt and investigate an incomplete run before retrying.
An occupied IP is an error, not permission to disconnect its owner.

## Receipts and limits

`recovery.json` records tool/input hashes, identities, final status, consistent
read revisions, cleanup errors and the active runtime name. A successful
`RECOVERED` result is an operational check, not an SLA guarantee or a new
acceptance/promotion result. Prior failed pilots and frozen scientific results
are not changed. No traffic, FlowBlocker, QoS policy or LLM is invoked.

Local guard tests (fake Docker, no daemon or server):

```bash
python3 -m unittest discover -s tests -p 'test_etcd2_member_recovery.py' -v
```

## Bounded post-recovery observation (read-only)

`check_etcd2_recovery.py` imports the **exact SHA256-pinned recovery helper**
that was applied successfully. It never calls the helper's recovery workflow.
It checks the original container guards, the replacement label/IP, three-member
status/membership and alarms before and after a small HTTP read sample. Each
member's loopback client URL is derived from Docker's IPv4 port bindings.

```bash
sudo -v
python3 scripts/check_etcd2_recovery.py \
  --receipt /absolute/path/to/etcd2-recovery-XXXXXXXX/recovery.json \
  --recovery-tool /absolute/path/to/comas-etcd2-recovery-e2d091826cc1.py \
  --samples-per-member 20
```

The only key-value RPC is an exact-key linearizable Range request, with
`keys_only=true` and `serializable=false`. There are no writes, retries,
`endpoint health` probes, starts/stops, configuration changes or repairs.
Environment proxies and redirects are disabled. The 1 s socket I/O timeout
matches the earlier diagnostic setting but is **not** a total deadline.

A new private sibling `etcd-post-recovery-*` directory retains the raw timings,
failures, status snapshots and input hashes in `read-check.json`. Failed reads
remain in the denominator; percentiles use successful samples only. A restart,
alarm or changed identity is reported, not repaired. `OBSERVED_READS_OK` means
only that the sampled reads and guards passed. It does not establish transaction
latency, stress resilience, elimination of historical timeouts or SLA promotion.

```bash
python3 -m unittest discover -s tests -p 'test_etcd_recovery_check.py' -v
```

## Offline consolidation of post-recovery shadow attempts

`predictive_sla_post_recovery_report.py` is separate from the traffic-pilot
reporter. It reads one frozen `qos-online-shadow-v2-diagnostics-post-recovery-*`
configuration and **every** directory under its `runs/`, not only the five
console-reported successes or the latest two repetitions.

It reuses the frozen diagnostic **loaders and trace parser only**; no preflight,
worker, HTTP request, Docker command, traffic or ETCD operation is invoked.
For final receipts it validates the per-file hash ledger, manifest bindings,
raw start/finish/store traces, domain summaries and confirmed-publication
journals. HTTP success alone cannot substitute for a validated atomic-pair ACK.
Attempts without final receipts remain inventory-only `UNFINALIZED_UNKNOWN`.
Invalid sources are retained as `UNVERIFIED`, not silently accepted/discarded.
Stopped but verifiable attempts and their failed requests remain in the totals.

```bash
python3 predictive_sla_post_recovery_report.py \
  --source-root /absolute/path/to/results/qos-online-shadow-v2-diagnostics-post-recovery-TIMESTAMP \
  --output /absolute/path/to/results/qos-shadow-post-recovery-report-TIMESTAMP
```

The output must be a new sibling directory, never inside the source. It contains
`manifest.json` (all source file hashes and directories), a sealed
`validation-summary.json`, and `validation-summary.md`. Source/config/code hashes
and the directory inventory are rechecked before publishing the report.
Missing known run IDs or invalid receipts produce exit 2 and a review-required
report. Unfinalized sources are explicitly disclosed; they do not contribute
fabricated zeros to metrics. HTTP latency is pooled from raw successful samples,
with failures/unfinished requests counted separately. Worker reads are separate
from preflight/launcher requests. The five runs were not a preregistered
five-repetition acceptance test and do not establish statistical independence,
SLA promotion, a guaranteed deadline or causal elimination of past timeouts.

The script can also be copied to a hash-named `/tmp` path and run with
`PYTHONPATH` set to the unchanged repository root. Existing frozen modules are
required; installing the new reporter does not change their code snapshots.

```bash
python3 -m unittest discover -s tests -p 'test_predictive_sla_post_recovery_report.py' -v
```

References:

- [ETCD runtime configuration](https://etcd.io/docs/v3.5/op-guide/runtime-configuration/)
- [Snapshot identity and integrity](https://etcd.io/docs/v3.5/op-guide/recovery/)
- [WAL restart metadata in 3.5.16](https://github.com/etcd-io/etcd/blob/v3.5.16/server/etcdserver/raft.go#L501)
- [Client readiness in 3.5.16](https://github.com/etcd-io/etcd/blob/v3.5.16/server/embed/serve.go#L94)
- [HTTP Range API and protobuf JSON representation](https://etcd.io/docs/v3.5/dev-guide/api_grpc_gateway/)
- [Range consistency and keys-only options](https://github.com/etcd-io/etcd/blob/v3.5.16/api/etcdserverpb/rpc.proto)

## One instrumented slow-ramp after a recovered-cluster timeout

`predictive_sla_instrumented_ramp.py` wraps the **unchanged** frozen slow-ramp
launcher. Create a new ramp protocol with `predictive_sla_shadow_ramp.py freeze`
using the post-recovery idle config and its original completed idle run. Never
reuse a failed ramp's directory. No tracked frozen module needs to change: the
wrapper can be copied to a hash-named `/tmp` path and imported with
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD"`.

Both `preflight` and `run` require `--protocol`, `--recovery-receipt`,
`--recovery-tool` and `--read-check-tool`. The two helpers are SHA256-pinned to
the versions applied/observed above. Only their read-only identity/status
checks are invoked, never their recovery or read-sampling workflows. The
original `etcd2` must remain stopped. Member identities, cgroup paths and source
hashes are rechecked afterward; containers are never started/stopped/repaired.

The read-only preflight requires the native lab safeguards plus accessible
Linux **cgroup v2**, CPU/memory/I/O pressure, `/proc/diskstats`, per-ETCD-container
CPU/throttling/memory/I/O counters, and each member's loopback `GET /metrics`.
Missing/unsupported data aborts before traffic; the wrapper will not install
packages, enable metrics, migrate cgroups or change runtime configuration.

```bash
sudo -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" python3 predictive_sla_instrumented_ramp.py run \
  --protocol /absolute/path/to/new-ramp/protocol.json \
  --recovery-receipt /absolute/path/to/etcd2-recovery-XXXXXXXX/recovery.json \
  --recovery-tool /absolute/path/to/comas-etcd2-recovery-e2d091826cc1.py \
  --read-check-tool /absolute/path/to/comas-etcd-read-check-0ef4c0ecb988.py \
  --allow-lab-traffic --allow-shadow-publication
```

Explicit traffic/publication flags are required before run preflight or file
creation. One attempt only, no pilot retry. The wrapper collects a 10 s
baseline, launches the existing supervisor in its own session, and observes
another 5 s after it exits. Nominal intervals: host/cgroups 1 s, all three
ETCD `/metrics` scrapes sequentially every 5 s. Metrics GETs disable proxies and
redirects and have a bounded body and 1 s socket timeout; this is **additional
monitoring traffic**, not resource isolation. The shadow request timeout,
model, workload, policy and cleanup code remain frozen. ETCD normal-state and
domain-table writes continue to share resources with the isolated namespace.

New `instrumentation/` files live outside native `pilot/` and shadow-run hash
ledgers: `observation-plan.json`, `host.ndjson`, `etcd-metrics.ndjson`, bounded
ETCD logs, `launcher.log`, and sealed `instrumentation-summary.json`. Records
have realtime/monotonic timestamps. Raw selected histogram buckets/counts/sums
are retained; interval means use **adjacent** successful scrape deltas only.
Failed scrapes are missing data, not zeros, and break the delta chain. Routine
scheduled observations continue, without immediate retries or automatic
repairs; the report discloses gaps and cannot be `OBSERVED_COMPLETED` with any
missing sample. Sampler errors do not authorize intervention in ETCD.

Ctrl-C/SIGTERM asks only the owned ramp supervisor to clean up via SIGINT. The
wrapper does not signal unrelated processes or SIGKILL a collector. If native
cleanup exceeds the bounded wait, it records the owned PID and a cleanup error;
do not begin another pilot until that state is investigated. Keep the terminal
open until the final receipt. Do not run competing lab experiments.

`OBSERVED_COMPLETED` means this attempt and its observation finished, **not**
deadline compliance, acceptance of v4, promotion, or proof of a bottleneck.
Native stopped receipts remain stopped and lead to `REVIEW_REQUIRED`. CPU PSI,
iowait, steal, throttling, diskstats and ETCD WAL/backend histograms must be
correlated with the exact failed request window before attributing cause. All
raw disk layers are retained; summing them double-counts I/O.

```bash
python3 -m unittest discover -s tests -p 'test_predictive_sla_instrumented_ramp.py' -v
```

References: [ETCD disk/server metrics](https://etcd.io/docs/v3.5/metrics/),
[Docker runtime metrics and cgroup v2](https://docs.docker.com/engine/containers/runmetrics/).
