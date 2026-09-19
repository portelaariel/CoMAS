import json
import tempfile
import threading
import unittest
from pathlib import Path

from experiments.evaluate_agentic_authority_run import (
    evaluate as evaluate_authority_run,
)
from experiments.evaluate_agentic_authority_campaign import (
    evaluate as evaluate_authority_campaign,
)
from experiments.evaluate_agentic_live_run import (
    evaluate as evaluate_agentic_live_run,
)
from experiments.evaluate_agentic_live_campaign import (
    evaluate as evaluate_agentic_live_campaign,
)
from experiments.evaluate_agentic_live_replication import (
    bootstrap_mean_interval,
    evaluate as evaluate_agentic_live_replication,
    wilson_interval,
)
from experiments.package_agentic_live_replication import (
    package_replication,
    verify_package,
)
from experiments.evaluate_agentic_runtime_faults import evaluate
from experiments.monitor_predictors import (
    flow_anomalies,
    flow_predictions,
    retain_new_agentic_events,
    retain_new_decision_events,
)
from experiments.run_mininet_workload import (
    domain_table_has_hosts,
    wait_for_attack_release,
)
from experiments.summarize_benchmark import (
    aggregate_metrics,
    markdown_table,
    summarize_run,
)


class BenchmarkToolTests(unittest.TestCase):
    @staticmethod
    def write_iperf(path, bits_per_second):
        path.write_text(json.dumps({
            "end": {"sum": {"bits_per_second": bits_per_second}}
        }), encoding="utf-8")

    def test_flow_anomalies_selects_only_requested_pair(self):
        payload = {
            "anomalies": [
                {"anomaly_id": "wanted", "meta": {
                    "nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"}},
                {"anomaly_id": "other", "meta": {
                    "nw_src": "10.0.0.2", "nw_dst": "10.0.0.8"}},
            ]
        }
        selected = flow_anomalies(payload, "10.0.0.1->10.0.0.8")
        self.assertEqual([row["anomaly_id"] for row in selected], ["wanted"])

        prediction_payload = {
            "predictions": [
                {"key": "wanted", "meta": {
                    "nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"}},
                {"key": "other", "meta": {
                    "nw_src": "10.0.0.2", "nw_dst": "10.0.0.8"}},
            ]
        }
        predictions = flow_predictions(
            prediction_payload, "10.0.0.1->10.0.0.8"
        )
        self.assertEqual([row["key"] for row in predictions], ["wanted"])

    def test_monitor_writes_each_agentic_transition_only_once(self):
        seen = set()
        payload = {
            "decision_events": [
                {"event_id": "event-2", "decision": "AGREED"},
                {"event_id": "event-1", "decision": "WAITING_PROPOSALS"},
            ],
            "decisions": [{"decision": "AGREED"}],
        }

        first = retain_new_agentic_events(payload, seen)
        second = retain_new_agentic_events(payload, seen)

        self.assertEqual(
            [row["event_id"] for row in first["decision_events"]],
            ["event-2", "event-1"],
        )
        self.assertEqual(second["decision_events"], [])
        self.assertEqual(second["decisions"], payload["decisions"])

    def test_monitor_writes_each_mcda_transition_only_once(self):
        seen = set()
        payload = {
            "decision_events": [{
                "event_id": "mcda:domain-0:flow:2:MITIGATE:10",
                "decision": "MITIGATE",
                "window_ids": [2],
            }],
            "decisions": [{"decision": "SUSPECT", "window_ids": [3]}],
        }

        first = retain_new_decision_events(payload, seen)
        second = retain_new_decision_events(payload, seen)

        self.assertEqual(len(first["decision_events"]), 1)
        self.assertEqual(second["decision_events"], [])
        self.assertEqual(second["decisions"], payload["decisions"])

    def test_domain_table_requires_both_mitigation_endpoints(self):
        payload = {"hosts": {"10.0.0.1": {"dpid": 1}}}
        self.assertFalse(domain_table_has_hosts(
            payload, "10.0.0.1", "10.0.0.8"
        ))
        payload["hosts"]["10.0.0.8"] = {"dpid": 4}
        self.assertTrue(domain_table_has_hosts(
            payload, "10.0.0.1", "10.0.0.8", 1, 4
        ))
        self.assertFalse(domain_table_has_hosts(
            payload, "10.0.0.1", "10.0.0.8", 1, 3
        ))

    def test_attack_gate_announces_readiness_and_waits_for_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = Path(tmp)
            result = []
            thread = threading.Thread(
                target=lambda: result.append(wait_for_attack_release(gate, 2.0))
            )
            thread.start()
            for _attempt in range(100):
                if (gate / "attack.ready.json").exists():
                    break
                threading.Event().wait(0.01)
            self.assertTrue((gate / "attack.ready.json").exists())
            self.assertTrue(thread.is_alive())
            (gate / "attack.release").touch()
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, [None])
            self.assertTrue((gate / "attack.released.json").exists())

    def test_runtime_fault_report_requires_fail_closed_and_fresh_recovery(self):
        flow = "10.0.0.1->10.0.0.8"

        def agent_payload(events, errors=0):
            return {
                "active": True,
                "mode": "shadow",
                "authoritative": False,
                "errors": errors,
                "decisions": [],
                "decision_events": events,
            }

        def event(cid, decision, entered_ns, proposals=None):
            return {
                "event_id": f"{cid}:{decision}:{entered_ns}",
                "flow": flow,
                "decision": decision,
                "state_entered_ns": entered_ns,
                "participating_domains": ["domain-0", "domain-1"],
                "proposals": proposals or [],
            }

        proposals = [
            {"cid": cid, "observation_ns": 120, "created_ns": 125}
            for cid in ("domain-0", "domain-1")
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows_by_episode = {
                "missing-agent": [
                    {"port": "6060", "status": {"cid": "domain-0"},
                     "agentic": agent_payload([
                         event("domain-0", "WAITING_PROPOSALS", 120)
                     ])},
                ],
                "missing-agent-recovery": [
                    {"port": str(6060 + index), "status": {"cid": f"domain-{index}"},
                     "agentic": agent_payload([
                         event(f"domain-{index}", "AGREED", 130, proposals)
                     ])}
                    for index in range(2)
                ],
                "etcd-partition": [
                    {"port": "6060", "status": {"cid": "domain-0"},
                     "agentic": agent_payload([], errors=0)},
                    {"port": "6060", "status": {"cid": "domain-0"},
                     "agentic": agent_payload([], errors=2)},
                ],
                "etcd-recovery": [
                    {"port": str(6060 + index), "status": {"cid": f"domain-{index}"},
                     "agentic": agent_payload([
                         event(f"domain-{index}", "AGREED", 140, proposals)
                     ])}
                    for index in range(2)
                ],
            }
            for name, rows in rows_by_episode.items():
                episode = root / name
                episode.mkdir()
                (episode / "attack_start_ns.txt").write_text("100\n", encoding="utf-8")
                (episode / "workload_status.json").write_text(
                    json.dumps({"valid": True}), encoding="utf-8"
                )
                (episode / "timeline.ndjson").write_text(
                    "".join(json.dumps(row) + "\n" for row in rows),
                    encoding="utf-8",
                )
            (root / "flowblocker-requests.log").write_text("", encoding="utf-8")

            report = evaluate(root, flow, 2)

            self.assertTrue(report["aggregate"]["safe"])
            self.assertEqual(report["aggregate"]["passed"], 4)
            self.assertTrue(report["global_checks"]["no_flowblocker_request"])

            stale = rows_by_episode["etcd-recovery"][0]["agentic"]["decision_events"][0]
            stale["proposals"][0]["observation_ns"] = 99
            (root / "etcd-recovery" / "timeline.ndjson").write_text(
                "".join(
                    json.dumps(row) + "\n"
                    for row in rows_by_episode["etcd-recovery"]
                ),
                encoding="utf-8",
            )
            unsafe = evaluate(root, flow, 2)
            self.assertFalse(unsafe["aggregate"]["safe"])

    def test_authority_dry_run_requires_one_claim_and_zero_actuation(self):
        flow = "10.0.0.1->10.0.0.8"
        attack_ns = 1_000_000_000
        domains = ("domain-0", "domain-1")
        proposals = [
            {
                "cid": cid,
                "observation_ns": attack_ns + 100_000_000,
                "created_ns": attack_ns + 200_000_000,
            }
            for cid in domains
        ]

        def row(cid, won):
            decision = {
                "event_id": f"{cid}:agreement",
                "flow": flow,
                "decision": "AGREED",
                "state_entered_ns": attack_ns + 500_000_000,
                "proposals": proposals,
                "authority": {
                    "authorized": True,
                    "claim": {
                        "won": won,
                        "degraded": False,
                        "coordinator": "domain-0",
                    },
                    "mcda_comparison": {
                        "available": True,
                        "matches": True,
                        "basis": "authority_evaluation",
                        "captured_ns": attack_ns + 450_000_000,
                        "mcda": {
                            "decision": "MITIGATE",
                            "evaluated_ns": attack_ns + 400_000_000,
                        },
                    },
                },
                "execution": {
                    "attempted": False,
                    "executed": False,
                    "would_execute": won,
                },
                "legacy_comparison": {
                    "available": True,
                    "matches": True,
                },
            }
            return {
                "sampled_ns": attack_ns + 600_000_000,
                "status": {"cid": cid},
                "agentic": {
                    "requested": True,
                    "active": True,
                    "mode": "authority-dry-run",
                    "authoritative": True,
                    "actuation_enabled": False,
                    "cid": cid,
                    "decisions": [decision],
                    "decision_events": [],
                },
            }

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-dry-run",
                "scenario": "ddos",
                "flow": flow,
                "controller_sets": 2,
                "agentic_enabled": True,
                "agentic_mode": "authority-dry-run",
            }), encoding="utf-8")
            (run_dir / "attack_start_ns.txt").write_text(
                f"{attack_ns}\n", encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            (run_dir / "summary.json").write_text(json.dumps({
                "runs": [{"classification": "TP"}],
            }), encoding="utf-8")
            rows = [row("domain-0", True), row("domain-1", False)]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            for switch in ("s1", "s2", "s3", "s4"):
                (run_dir / f"ovs-flows-{switch}.txt").write_text(
                    "actions=NORMAL\n", encoding="utf-8"
                )
            (run_dir / "flow-blocker-0.log").write_text("", encoding="utf-8")

            report = evaluate_authority_run(run_dir)
            self.assertTrue(report["aggregate"]["safe"])
            self.assertEqual(report["claim_winner_domains"], ["domain-0"])
            self.assertEqual(report["would_execute_domains"], ["domain-0"])

            # Repeated polling preserves older authorized AGREED events. A
            # mismatch in an earlier observation must not override the newer
            # per-domain comparison that agrees at authority evaluation.
            for item in rows:
                current = item["agentic"]["decisions"][0]
                historical = json.loads(json.dumps(current))
                historical["event_id"] += ":historical-mismatch"
                historical["state_entered_ns"] = attack_ns + 300_000_000
                historical["authority"]["claim"]["won"] = False
                historical["authority"]["mcda_comparison"].update({
                    "matches": False,
                    "captured_ns": attack_ns + 300_000_000,
                    "mcda": {
                        "decision": "CORROBORATED",
                        "evaluated_ns": attack_ns + 250_000_000,
                    },
                })
                historical["execution"]["would_execute"] = False
                item["agentic"]["decision_events"] = [historical]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            canonical_mcda = evaluate_authority_run(run_dir)
            self.assertTrue(canonical_mcda["aggregate"]["safe"])
            self.assertTrue(canonical_mcda["checks"]["agent_matches_mcda"])

            # The inverse ordering must remain unsafe: a newer mismatch cannot
            # be hidden by an older matching observation.
            for item in rows:
                comparison = item["agentic"]["decisions"][0]["authority"][
                    "mcda_comparison"
                ]
                comparison.update({
                    "matches": False,
                    "captured_ns": attack_ns + 700_000_000,
                    "mcda": {
                        "decision": "CORROBORATED",
                        "evaluated_ns": attack_ns + 650_000_000,
                    },
                })
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            latest_mismatch = evaluate_authority_run(run_dir)
            self.assertFalse(latest_mismatch["aggregate"]["safe"])
            self.assertFalse(latest_mismatch["checks"]["agent_matches_mcda"])
            for item in rows:
                item["agentic"]["decision_events"] = []
                item["agentic"]["decisions"][0]["authority"][
                    "mcda_comparison"
                ].update({
                    "matches": True,
                    "captured_ns": attack_ns + 450_000_000,
                    "mcda": {
                        "decision": "MITIGATE",
                        "evaluated_ns": attack_ns + 400_000_000,
                    },
                })

            # A comparação é evidência experimental, não parte do gate de
            # autoridade. Se a decisão corrente do MCDA já avançou, o
            # avaliador deve correlacionar o episódio preservado no histórico.
            for item in rows:
                decision = item["agentic"]["decisions"][0]
                decision["window_ids"] = [2]
                decision["legacy_comparison"] = {
                    "available": False,
                    "matches": None,
                    "reason": "decisão MCDA pertence a outro episódio",
                }
                cid = item["status"]["cid"]
                item["collaboration"] = {
                    "cid": cid,
                    "decisions": [{
                        "flow": flow,
                        "decision": "SUSPECT",
                        "evaluated_ns": attack_ns + 800_000_000,
                        "window_ids": [3],
                    }],
                    "decision_events": [{
                        "flow": flow,
                        "decision": "MITIGATE",
                        "evaluated_ns": attack_ns + 400_000_000,
                        "window_ids": [2],
                    }],
                }
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            historical_mcda = evaluate_authority_run(run_dir)
            self.assertTrue(historical_mcda["aggregate"]["safe"])
            self.assertTrue(
                historical_mcda["checks"]["mcda_comparison_available"]
            )
            self.assertTrue(historical_mcda["checks"]["agent_matches_mcda"])

            rows[0]["agentic"]["decisions"][0]["execution"]["attempted"] = True
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            unsafe = evaluate_authority_run(run_dir)
            self.assertFalse(unsafe["aggregate"]["safe"])
            self.assertFalse(unsafe["checks"]["agent_never_actuated"])

            rows[0]["agentic"]["decisions"][0]["execution"]["attempted"] = False
            rows[1]["agentic"]["decisions"][0]["authority"]["claim"][
                "coordinator"
            ] = "domain-1"
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            split_brain = evaluate_authority_run(run_dir)
            self.assertFalse(split_brain["aggregate"]["safe"])
            self.assertFalse(split_brain["checks"]["claim_owner_consistent"])

    def test_authority_dry_run_benign_forbids_authorization(self):
        flow = "10.0.0.1->10.0.0.8"
        started_ns = 1_000_000_000

        def agent_row(cid):
            return {
                "sampled_ns": started_ns + 100_000_000,
                "status": {"cid": cid},
                "agentic": {
                    "requested": True,
                    "active": True,
                    "mode": "authority-dry-run",
                    "authoritative": True,
                    "actuation_enabled": False,
                    "cid": cid,
                    "decisions": [],
                    "decision_events": [],
                },
            }

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-dry-run",
                "scenario": "benign",
                "flow": flow,
                "controller_sets": 2,
                "started_ns": started_ns,
                "agentic_enabled": True,
                "agentic_mode": "authority-dry-run",
            }), encoding="utf-8")
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            (run_dir / "summary.json").write_text(json.dumps({
                "runs": [{"classification": "TN"}],
            }), encoding="utf-8")
            rows = [agent_row("domain-0"), agent_row("domain-1")]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            (run_dir / "ovs-flows-s1.txt").write_text(
                "actions=NORMAL\n", encoding="utf-8"
            )

            report = evaluate_authority_run(run_dir)
            self.assertTrue(report["aggregate"]["safe"])
            self.assertTrue(report["checks"]["benchmark_tn"])
            self.assertTrue(report["checks"]["no_agent_authorization"])

            forged = {
                "event_id": "forged-benign-agreement",
                "flow": flow,
                "decision": "AGREED",
                "state_entered_ns": started_ns + 50_000_000,
                "authority": {
                    "authorized": True,
                    "claim": {"won": True, "coordinator": "domain-0"},
                },
                "execution": {
                    "attempted": False,
                    "executed": False,
                    "would_execute": True,
                },
            }
            rows[0]["agentic"]["decisions"] = [forged]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            unsafe = evaluate_authority_run(run_dir)
            self.assertFalse(unsafe["aggregate"]["safe"])
            self.assertFalse(unsafe["checks"]["no_agent_authorization"])
            self.assertFalse(unsafe["checks"]["no_would_execute"])

    def test_agentic_live_canary_requires_exclusive_agent_execution(self):
        flow = "10.0.0.1->10.0.0.8"
        attack_ns = 1_000_000_000

        def row(cid, won):
            execution = {
                "attempted": won,
                "executed": won,
                "would_execute": won,
                "owner": "agentic",
                "reason": "FlowBlocker HTTP 200" if won else "peer coordena",
            }
            event = {
                "event_id": f"{cid}:live",
                "flow": flow,
                "decision": "AGREED",
                "window_ids": [2],
                "state_entered_ns": attack_ns + 500_000_000,
                "authority": {
                    "evaluated_ns": attack_ns + 500_000_000,
                    "authorized": True,
                    "claim": {
                        "won": won,
                        "degraded": False,
                        "coordinator": "domain-0",
                    },
                    "mcda_comparison": {
                        "available": True,
                        "matches": True,
                        "basis": "authority_evaluation",
                        "captured_ns": attack_ns + 500_000_000,
                        "mcda": {
                            "decision": "MITIGATE",
                            "evaluated_ns": attack_ns + 400_000_000,
                            "window_ids": [2],
                        },
                    },
                },
                "execution": execution,
            }
            return {
                "sampled_ns": attack_ns + 600_000_000,
                "status": {"cid": cid},
                "agentic": {
                    "requested": True,
                    "active": True,
                    "mode": "authority-live",
                    "authoritative": True,
                    "actuation_enabled": True,
                    "cid": cid,
                    "decisions": [event],
                    "decision_events": [],
                },
                "collaboration": {
                    "cid": cid,
                    "decisions": [{
                        "flow": flow,
                        "decision": "MITIGATE",
                        "evaluated_ns": attack_ns + 400_000_000,
                        "window_ids": [2],
                        "claim": None,
                        "mitigation": {
                            "attempted": False,
                            "executed": False,
                            "owner": "agentic",
                        },
                    }],
                },
            }

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            metadata = {
                "mode": "agentic-live",
                "scenario": "ddos",
                "flow": flow,
                "controller_sets": 2,
                "started_ns": attack_ns - 100_000_000,
                "agentic_enabled": True,
                "agentic_mode": "authority-live",
            }
            (run_dir / "metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            (run_dir / "attack_start_ns.txt").write_text(
                str(attack_ns), encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            (run_dir / "summary.json").write_text(json.dumps({
                "runs": [{"classification": "TP", "mitigation_executed": True}],
            }), encoding="utf-8")
            rows = [row("domain-0", True), row("domain-1", False)]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            (run_dir / "flow-blocker-0.log").write_text(
                "Service request to block traffic\n", encoding="utf-8"
            )
            (run_dir / "ovs-flows-s1.txt").write_text(
                "ip,nw_src=10.0.0.1,nw_dst=10.0.0.8 actions=drop\n",
                encoding="utf-8",
            )

            report = evaluate_agentic_live_run(run_dir)
            self.assertTrue(report["aggregate"]["safe"])
            self.assertEqual(report["winner_domains"], ["domain-0"])
            self.assertEqual(report["execution_domains"], ["domain-0"])
            self.assertTrue(report["agentic_matches_mcda"])
            self.assertTrue(report["mcda_converged_within_bound"])

            # Uma divergência instantânea do observador não invalida a
            # segurança agentic. A convergência deve ocorrer no mesmo episódio
            # e dentro do limite experimental.
            comparison = rows[0]["agentic"]["decisions"][0]["authority"][
                "mcda_comparison"
            ]
            comparison.update({
                "matches": False,
                "mcda": {
                    "decision": "CORROBORATED",
                    "evaluated_ns": attack_ns + 400_000_000,
                    "window_ids": [2],
                },
            })
            rows[0]["collaboration"]["decisions"][0].update({
                "decision": "CORROBORATED",
                "evaluated_ns": attack_ns + 400_000_000,
            })
            converged = json.loads(json.dumps(rows[0]))
            converged["sampled_ns"] = attack_ns + 1_100_000_000
            converged["collaboration"]["decisions"] = [{
                "flow": flow,
                "decision": "MITIGATE",
                "evaluated_ns": attack_ns + 1_000_000_000,
                "window_ids": [2],
                "claim": None,
                "mitigation": {
                    "attempted": False,
                    "executed": False,
                    "owner": "agentic",
                },
            }]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows + [converged]),
                encoding="utf-8",
            )
            lagged = evaluate_agentic_live_run(run_dir)
            self.assertTrue(lagged["aggregate"]["safe"])
            self.assertFalse(lagged["agentic_matches_mcda"])
            self.assertFalse(
                lagged["observational_checks"][
                    "agent_matches_mcda_at_authority"
                ]
            )
            self.assertTrue(lagged["mcda_converged_within_bound"])
            self.assertEqual(
                lagged["mcda_convergence"]["domain-0"]["latency_ms"], 500.0
            )

            # A definição v2 também reconhece um MITIGATE anterior, mas
            # somente dentro do lookback e na janela imediatamente anterior.
            early = json.loads(json.dumps(rows[0]))
            early["sampled_ns"] = attack_ns + 550_000_000
            early["collaboration"]["decisions"] = [{
                "flow": flow,
                "decision": "MITIGATE",
                "evaluated_ns": attack_ns + 100_000_000,
                "window_ids": [1],
                "claim": None,
                "mitigation": {
                    "attempted": False,
                    "executed": False,
                    "owner": "agentic",
                },
            }]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows + [early]),
                encoding="utf-8",
            )
            anticipated = evaluate_agentic_live_run(run_dir)
            domain_0 = anticipated["mcda_convergence"]["domain-0"]
            self.assertTrue(anticipated["mcda_converged_within_bound"])
            self.assertEqual(domain_0["direction"], "BEFORE_AUTHORITY")
            self.assertEqual(domain_0["window_relation"], "PRECEDING")
            self.assertEqual(domain_0["preceding_window_distance"], 1)
            self.assertEqual(domain_0["offset_ms"], -400.0)
            self.assertEqual(domain_0["latency_ms"], 0.0)
            self.assertEqual(domain_0["lead_ms"], 400.0)

            outside_lookback = evaluate_agentic_live_run(
                run_dir, mcda_episode_lookback_ms=200.0
            )
            self.assertFalse(
                outside_lookback["mcda_convergence"]["domain-0"]["converged"]
            )

            early["collaboration"]["decisions"][0]["window_ids"] = [0]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows + [early]),
                encoding="utf-8",
            )
            too_many_windows = evaluate_agentic_live_run(run_dir)
            self.assertFalse(
                too_many_windows["mcda_convergence"]["domain-0"]["converged"]
            )

            early["collaboration"]["decisions"][0].update({
                "evaluated_ns": attack_ns - 100_000_000,
                "window_ids": [1],
            })
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows + [early]),
                encoding="utf-8",
            )
            before_attack_gate = evaluate_agentic_live_run(run_dir)
            self.assertFalse(
                before_attack_gate["mcda_convergence"]["domain-0"]["converged"]
            )

            rows[0]["collaboration"]["decisions"][0]["claim"] = {
                "won": True,
            }
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in rows),
                encoding="utf-8",
            )
            unsafe = evaluate_agentic_live_run(run_dir)
            self.assertFalse(unsafe["checks"]["mcda_never_claimed"])
            self.assertFalse(unsafe["aggregate"]["safe"])

    def test_agentic_live_campaign_requires_paired_safe_cases(self):
        flow = "10.0.0.1->10.0.0.8"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "schema_version": 2,
                "minimums": {"ddos": 1, "benign": 1, "distinct_flows": 1},
                "mcda_convergence_window_ms": 1000,
                "mcda_episode_definition": {
                    "name": "bounded-episode-window-v2",
                    "lookback_ms": 2000.0,
                    "max_preceding_windows": 1,
                    "future_convergence_ms": 1000.0,
                },
                "prerequisites": {
                    "promotion_ready": True,
                    "canary_ready": True,
                    "promotion_commit": "commit-a",
                    "model_sha256": "model-a",
                },
                "cases": [
                    {"case_id": "01-benign", "pair_id": "01-h1-h8",
                     "scenario": "benign", "flow": flow},
                    {"case_id": "01-ddos", "pair_id": "01-h1-h8",
                     "scenario": "ddos", "flow": flow},
                ],
            }
            (root / "campaign-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            common = {
                "schema_version": 2,
                "flow": flow,
                "active_domains": ["domain-0", "domain-1"],
                "git_commit": "commit-a",
                "model_sha256": "model-a",
                "flowblocker_requests": 0,
                "drop_rule_files": [],
                "detection_latency_ms": None,
                "mcda_consensus_latency_ms": None,
                "agentic_consensus_latency_ms": None,
                "ping_after_loss_percent": 0.0,
                "agentic_matches_mcda": None,
                "agentic_mcda_comparisons": {},
                "mcda_converged_within_bound": None,
                "mcda_max_convergence_latency_ms": None,
                "mcda_max_early_lead_ms": None,
                "mcda_convergence_window_ms": 1000.0,
                "mcda_episode_definition": {
                    "name": "bounded-episode-window-v2",
                    "lookback_ms": 2000.0,
                    "max_preceding_windows": 1,
                    "future_convergence_ms": 1000.0,
                },
                "mcda_convergence": {},
                "mcda_convergence_directions": {},
                "checks": {},
                "aggregate": {"safe": True},
            }
            benign = {
                **common,
                "scenario": "benign",
                "classification": "TN",
                "authorized_domains": [],
                "winner_domains": [],
                "execution_domains": [],
            }
            ddos = {
                **common,
                "scenario": "ddos",
                "classification": "TP",
                "authorized_domains": ["domain-0", "domain-1"],
                "winner_domains": ["domain-0"],
                "execution_domains": ["domain-0"],
                "flowblocker_requests": 1,
                "drop_rule_files": ["ovs-flows-s1.txt", "ovs-flows-s4.txt"],
                "detection_latency_ms": 500.0,
                "mcda_consensus_latency_ms": 900.0,
                "agentic_consensus_latency_ms": 1200.0,
                "ping_after_loss_percent": 100.0,
                "agentic_matches_mcda": False,
                "agentic_mcda_comparisons": {
                    "domain-0": {"matches": False},
                    "domain-1": {"matches": True},
                },
                "mcda_converged_within_bound": True,
                "mcda_max_convergence_latency_ms": 588.775,
                "mcda_max_early_lead_ms": 300.0,
                "mcda_convergence": {
                    "domain-0": {"direction": "BEFORE_AUTHORITY"},
                    "domain-1": {"direction": "AT_AUTHORITY"},
                },
                "mcda_convergence_directions": {
                    "BEFORE_AUTHORITY": 1,
                    "AT_AUTHORITY": 1,
                    "AFTER_AUTHORITY": 0,
                    "NOT_OBSERVED": 0,
                },
            }
            for case_id, payload in (("01-benign", benign), ("01-ddos", ddos)):
                case_dir = root / case_id
                case_dir.mkdir()
                (case_dir / "agentic-live-summary.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                (case_dir / "benchmark-exit-code.txt").write_text(
                    "0\n", encoding="utf-8"
                )
                (case_dir / "evaluator-exit-code.txt").write_text(
                    "0\n", encoding="utf-8"
                )

            report = evaluate_agentic_live_campaign(root)
            self.assertTrue(report["aggregate"]["campaign_ready"])
            self.assertEqual(report["metrics"]["TP"], 1)
            self.assertEqual(report["metrics"]["TN"], 1)
            self.assertEqual(
                report["metrics"]["agent_to_mcda_agreement_rate"], 0.0
            )
            self.assertEqual(
                report["metrics"]["agent_to_mcda_domain_agreement_rate"], 0.5
            )
            self.assertEqual(
                report["metrics"]["mcda_bounded_convergence_rate"], 1.0
            )
            self.assertEqual(
                report["metrics"]["mcda_convergence_direction_distribution"],
                {"AT_AUTHORITY": 1, "BEFORE_AUTHORITY": 1},
            )
            self.assertTrue(report["aggregate"]["operational_ready"])
            self.assertTrue(report["aggregate"]["comparative_ready"])

            ddos["mcda_episode_definition"]["lookback_ms"] = 1000.0
            (root / "01-ddos" / "agentic-live-summary.json").write_text(
                json.dumps(ddos), encoding="utf-8"
            )
            changed_definition = evaluate_agentic_live_campaign(root)
            self.assertTrue(changed_definition["aggregate"]["operational_ready"])
            self.assertFalse(changed_definition["aggregate"]["comparative_ready"])
            self.assertFalse(
                changed_definition["checks"]["single_mcda_episode_definition"]
            )
            ddos["mcda_episode_definition"]["lookback_ms"] = 2000.0
            (root / "01-ddos" / "agentic-live-summary.json").write_text(
                json.dumps(ddos), encoding="utf-8"
            )

            benign["execution_domains"] = ["domain-0"]
            (root / "01-benign" / "agentic-live-summary.json").write_text(
                json.dumps(benign), encoding="utf-8"
            )
            unsafe = evaluate_agentic_live_campaign(root)
            self.assertFalse(unsafe["aggregate"]["campaign_ready"])
            self.assertFalse(unsafe["checks"]["all_benign_rejected"])

    def test_agentic_live_replication_requires_balanced_frozen_protocol(self):
        protocol = {
            "10.0.0.1->10.0.0.8": ("h1", "h8", "1M", "50M"),
            "10.0.0.2->10.0.0.7": ("h2", "h7", "2M", "100M"),
            "10.0.0.3->10.0.0.6": ("h3", "h6", "5M", "150M"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pilot_path = root / "pilot.json"
            pilot_path.write_text(json.dumps({
                "schema_version": 2,
                "mcda_episode_definition": {
                    "name": "bounded-episode-window-v2",
                    "lookback_ms": 2000.0,
                    "max_preceding_windows": 1,
                    "future_convergence_ms": 1000.0,
                },
                "aggregate": {
                    "campaign_ready": True,
                    "operational_ready": True,
                    "comparative_ready": True,
                }
            }), encoding="utf-8")
            (root / "replication-manifest.json").write_text(json.dumps({
                "schema_version": 2,
                "mode": "agentic-live-statistical-replication",
                "design": {
                    "runs_per_scenario": 9,
                    "repetitions_per_flow": 3,
                    "distinct_flows": 3,
                    "bootstrap_resamples": 100,
                    "bootstrap_seed": 7,
                    "mcda_episode_definition": {
                        "name": "bounded-episode-window-v2",
                        "lookback_ms": 2000.0,
                        "max_preceding_windows": 1,
                        "future_convergence_ms": 1000.0,
                    },
                },
                "baseline": {
                    "pilot_report": str(pilot_path),
                    "model_sha256": "model-a",
                },
                "runtime": {
                    "git_commit": "commit-a",
                    "model_sha256": "model-a",
                },
                "execution": {
                    "tracked_tree_clean": True,
                    "disk_preflight_passed": True,
                    "campaign_exit_code": 0,
                    "campaign_summary": (
                        "agentic-live-campaign-test/campaign-summary.json"
                    ),
                },
            }), encoding="utf-8")
            campaign_root = root / "agentic-live-campaign-test"
            campaign_root.mkdir()
            manifest_cases = []
            rows = []
            for repetition in range(3):
                for flow, (source, destination, baseline, attack) in protocol.items():
                    pair_id = f"{repetition}-{source}-{destination}"
                    for scenario in ("benign", "ddos"):
                        case_id = f"{pair_id}-{scenario}"
                        manifest_cases.append({
                            "case_id": case_id,
                            "pair_id": pair_id,
                            "scenario": scenario,
                            "flow": flow,
                            "baseline_rate": baseline,
                            "attack_rate": attack,
                        })
                        is_attack = scenario == "ddos"
                        rows.append({
                            "case_id": case_id,
                            "expected_scenario": scenario,
                            "expected_flow": flow,
                            "classification": "TP" if is_attack else "TN",
                            "passed": True,
                            "git_commit": "commit-a",
                            "model_sha256": "model-a",
                            "detection_latency_ms": 500 + repetition if is_attack else None,
                            "mcda_consensus_latency_ms": 800 + repetition if is_attack else None,
                            "agentic_consensus_latency_ms": 1100 + repetition if is_attack else None,
                            "mcda_max_convergence_latency_ms": 300 + repetition if is_attack else None,
                        })
            (campaign_root / "campaign-manifest.json").write_text(
                json.dumps({
                    "schema_version": 2,
                    "mcda_episode_definition": {
                        "name": "bounded-episode-window-v2",
                        "lookback_ms": 2000.0,
                        "max_preceding_windows": 1,
                        "future_convergence_ms": 1000.0,
                    },
                    "cases": manifest_cases,
                }), encoding="utf-8"
            )
            campaign_payload = {
                "schema_version": 2,
                "mcda_episode_definition": {
                    "name": "bounded-episode-window-v2",
                    "lookback_ms": 2000.0,
                    "max_preceding_windows": 1,
                    "future_convergence_ms": 1000.0,
                },
                "cases": rows,
                "aggregate": {
                    "campaign_ready": True,
                    "operational_ready": True,
                    "comparative_ready": True,
                },
                "metrics": {
                    "agent_to_mcda_agreement_rate": 0.888889,
                    "agent_to_mcda_domain_agreement_rate": 0.944444,
                    "mcda_bounded_convergence_rate": 1.0,
                    "mcda_convergence_direction_distribution": {
                        "BEFORE_AUTHORITY": 6,
                        "AT_AUTHORITY": 6,
                        "AFTER_AUTHORITY": 6,
                    },
                    "winner_distribution": {"domain-0": 5, "domain-1": 4},
                },
            }
            (campaign_root / "campaign-summary.json").write_text(
                json.dumps(campaign_payload), encoding="utf-8"
            )

            report = evaluate_agentic_live_replication(
                root, bootstrap_resamples=100, bootstrap_seed=7
            )
            self.assertEqual(report["schema_version"], 3)
            self.assertTrue(report["aggregate"]["replication_ready"])
            self.assertTrue(
                report["aggregate"]["operational_replication_ready"]
            )
            self.assertTrue(
                report["aggregate"]["comparative_replication_ready"]
            )
            self.assertTrue(report["aggregate"]["joint_replication_ready"])
            self.assertEqual(report["metrics"]["TP"], 9)
            self.assertEqual(report["metrics"]["TN"], 9)
            self.assertLess(report["metrics"]["sensitivity_ci95"]["low"], 1.0)
            self.assertEqual(
                report["metrics"]["latencies"]["detection_latency_ms"]["n"],
                9,
            )

            (root / "replication-summary.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            package = package_replication(root)
            artifact = root / "research-artifact-v1"
            self.assertEqual(package["generated_file_count"], 7)
            self.assertTrue((artifact / "REPORT.md").is_file())
            self.assertTrue((artifact / "cases.csv").is_file())
            self.assertTrue((artifact / "mcda-convergence.csv").is_file())
            self.assertIn(
                "Hipótese operacional",
                (artifact / "REPORT.md").read_text(encoding="utf-8"),
            )
            artifact_manifest = json.loads(
                (artifact / "artifact-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                artifact_manifest["readiness"][
                    "operational_replication_ready"
                ],
                True,
            )
            self.assertGreater(artifact_manifest["source_file_count"], 3)
            self.assertTrue(verify_package(root)["valid"])
            (artifact / "cases.csv").write_text("alterado\n", encoding="utf-8")
            integrity = verify_package(root)
            self.assertFalse(integrity["valid"])
            self.assertEqual(integrity["mismatches"][0]["path"], (
                "research-artifact-v1/cases.csv"
            ))

            # Uma divergência MCDA torna o gate comparativo e o status do
            # runner falsos, mas não deve apagar a confirmação operacional.
            replication_manifest_path = root / "replication-manifest.json"
            replication_manifest = json.loads(
                replication_manifest_path.read_text(encoding="utf-8")
            )
            replication_manifest["execution"]["campaign_exit_code"] = 1
            replication_manifest_path.write_text(
                json.dumps(replication_manifest), encoding="utf-8"
            )
            campaign_payload["aggregate"].update({
                "campaign_ready": False,
                "operational_ready": True,
                "comparative_ready": False,
            })
            campaign_payload["metrics"].update({
                "mcda_bounded_convergence_rate": 0.888889,
                "mcda_convergence_direction_distribution": {
                    "BEFORE_AUTHORITY": 2,
                    "AT_AUTHORITY": 13,
                    "AFTER_AUTHORITY": 2,
                    "NOT_OBSERVED": 1,
                },
            })
            (campaign_root / "campaign-summary.json").write_text(
                json.dumps(campaign_payload), encoding="utf-8"
            )
            divergent = evaluate_agentic_live_replication(
                root, bootstrap_resamples=100, bootstrap_seed=7
            )
            self.assertTrue(
                divergent["aggregate"]["operational_replication_ready"]
            )
            self.assertFalse(
                divergent["aggregate"]["comparative_replication_ready"]
            )
            self.assertFalse(
                divergent["aggregate"]["joint_replication_ready"]
            )
            self.assertFalse(divergent["aggregate"]["replication_ready"])
            self.assertEqual(
                divergent["check_scopes"]["operational"]["failed_checks"], []
            )
            self.assertEqual(
                divergent["check_scopes"]["comparative"]["failed_checks"],
                ["comparative_ready"],
            )
            self.assertEqual(
                divergent["check_scopes"]["joint"]["failed_checks"],
                [
                    "campaign_process_succeeded",
                    "campaign_ready",
                    "comparative_ready",
                ],
            )

            replication_manifest["execution"]["campaign_exit_code"] = 0
            replication_manifest_path.write_text(
                json.dumps(replication_manifest), encoding="utf-8"
            )
            campaign_payload["aggregate"].update({
                "campaign_ready": True,
                "operational_ready": True,
                "comparative_ready": True,
            })
            campaign_payload["metrics"].update({
                "mcda_bounded_convergence_rate": 1.0,
                "mcda_convergence_direction_distribution": {
                    "BEFORE_AUTHORITY": 6,
                    "AT_AUTHORITY": 6,
                    "AFTER_AUTHORITY": 6,
                },
            })

            campaign_payload["mcda_episode_definition"]["lookback_ms"] = 1000.0
            (campaign_root / "campaign-summary.json").write_text(
                json.dumps(campaign_payload), encoding="utf-8"
            )
            changed_protocol = evaluate_agentic_live_replication(
                root, bootstrap_resamples=100, bootstrap_seed=7
            )
            self.assertFalse(changed_protocol["aggregate"]["replication_ready"])
            self.assertFalse(
                changed_protocol["checks"]["campaign_episode_definition_matches"]
            )
            campaign_payload["mcda_episode_definition"]["lookback_ms"] = 2000.0

            rows.pop()
            (campaign_root / "campaign-summary.json").write_text(json.dumps({
                **campaign_payload, "cases": rows,
            }), encoding="utf-8")
            unbalanced = evaluate_agentic_live_replication(
                root, bootstrap_resamples=100, bootstrap_seed=7
            )
            self.assertFalse(unbalanced["aggregate"]["replication_ready"])
            self.assertFalse(unbalanced["checks"]["expected_case_count"])

    def test_replication_confidence_intervals_are_deterministic(self):
        interval = wilson_interval(9, 9)
        self.assertEqual(interval["estimate"], 1.0)
        self.assertGreater(interval["low"], 0.7)
        self.assertLess(interval["low"], 0.71)
        first = bootstrap_mean_interval([1, 2, 3], resamples=100, seed=11)
        second = bootstrap_mean_interval([1, 2, 3], resamples=100, seed=11)
        self.assertEqual(first, second)
        self.assertLessEqual(first["low"], 2.0)
        self.assertGreaterEqual(first["high"], 2.0)

    def test_agentic_live_summary_uses_agent_claim_and_mcda_observation(self):
        flow = "10.0.0.1->10.0.0.8"
        attack_ns = 1_000_000_000

        def row(cid, won):
            event = {
                "event_id": f"{cid}:live-summary",
                "flow": flow,
                "decision": "AGREED",
                "evaluated_ns": attack_ns + 450_000_000,
                "state_entered_ns": attack_ns + 450_000_000,
                "authority": {
                    "authorized": True,
                    "claim": {
                        "won": won,
                        "degraded": False,
                        "coordinator": "domain-0",
                        "claimed_ns": attack_ns + 500_000_000,
                    },
                },
                "execution": {
                    "attempted": won,
                    "executed": won,
                    "would_execute": won,
                    "owner": "agentic",
                    "reason": "FlowBlocker HTTP 200" if won else "peer coordena",
                },
                "legacy_comparison": {
                    "available": True,
                    "matches": True,
                    "mcda": {
                        "decision": "MITIGATE",
                        "evaluated_ns": attack_ns + 400_000_000,
                    },
                },
            }
            return {
                "sampled_ns": attack_ns + 600_000_000,
                "status": {"cid": cid},
                "agentic": {
                    "requested": True,
                    "active": True,
                    "mode": "authority-live",
                    "authoritative": True,
                    "actuation_enabled": True,
                    "cid": cid,
                    "decisions": [event],
                    "decision_events": [],
                },
                "collaboration": {"decisions": [{
                    "flow": flow,
                    "decision": "MITIGATE",
                    "score": 0.95,
                    "confirming_domains": ["domain-0", "domain-1"],
                    "evaluated_ns": attack_ns + 400_000_000,
                    "claim": None,
                    "mitigation": {
                        "attempted": False,
                        "executed": False,
                        "owner": "agentic",
                    },
                }]},
                "anomalies": ([{
                    "anomaly_id": "attack",
                    "kind": "THROUGHPUT_SPIKE",
                    "ts_detect_ns": attack_ns + 100_000_000,
                    "mitigation": {
                        "attempted": True,
                        "executed": True,
                        "reason": "FlowBlocker HTTP 200",
                    },
                }] if won else []),
            }

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "agentic-live",
                "scenario": "ddos",
                "flow": flow,
                "controller_sets": 2,
                "started_ns": attack_ns - 100_000_000,
                "agentic_enabled": True,
                "agentic_mode": "authority-live",
            }), encoding="utf-8")
            (run_dir / "attack_start_ns.txt").write_text(
                str(attack_ns), encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(json.dumps({
                "valid": True,
                "attack_disrupted": True,
            }), encoding="utf-8")
            self.write_iperf(run_dir / "baseline.json", 1_000_000.0)
            (run_dir / "ping_before.txt").write_text(
                "0% packet loss\n", encoding="utf-8"
            )
            (run_dir / "ping_after.txt").write_text(
                "100% packet loss\n", encoding="utf-8"
            )
            initial_rows = [row("domain-0", True), row("domain-1", False)]
            post_drop_rows = json.loads(json.dumps(initial_rows))
            for item in post_drop_rows:
                item["sampled_ns"] = attack_ns + 900_000_000
                current = item["agentic"]["decisions"][0]
                preserved = json.loads(json.dumps(current))
                item["agentic"]["decision_events"] = [preserved]
                current["evaluated_ns"] = attack_ns + 900_000_000
                current["legacy_comparison"] = {
                    "available": True,
                    "matches": False,
                    "mcda": {
                        "decision": "CORROBORATED",
                        "evaluated_ns": attack_ns + 850_000_000,
                    },
                }
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(item) + "\n" for item in (
                    initial_rows + post_drop_rows
                )),
                encoding="utf-8",
            )

            report = summarize_run(run_dir)

            self.assertEqual(report["classification"], "TP")
            self.assertTrue(report["mitigation_executed"])
            self.assertEqual(report["coordinator"], "domain-0")
            self.assertEqual(report["consensus_latency_ms"], 400.0)
            self.assertEqual(report["mcda_consensus_latency_ms"], 300.0)
            self.assertEqual(
                report["agentic_active_domains"], ["domain-0", "domain-1"]
            )
            self.assertTrue(report["agentic_matches_mcda"])
            self.assertEqual(
                {item["basis"] for item in report["agentic_mcda_comparisons"]},
                {"first_event_observation"},
            )

    def test_authority_campaign_requires_positive_and_negative_cases(self):
        flow = "10.0.0.1->10.0.0.8"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "minimums": {"ddos": 1, "benign": 1, "distinct_flows": 1},
                "cases": [
                    {"case_id": "01-ddos", "scenario": "ddos", "flow": flow},
                    {"case_id": "01-benign", "scenario": "benign", "flow": flow},
                ],
            }
            (root / "campaign-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            ddos = {
                "scenario": "ddos",
                "flow": flow,
                "classification": "TP",
                "authorized_domains": ["domain-0", "domain-1"],
                "claim_winner_domains": ["domain-0"],
                "would_execute_domains": ["domain-0"],
                "flowblocker_requests": 0,
                "drop_rule_files": [],
                "git_commit": "commit-a",
                "model_sha256": "model-a",
                "detection_latency_ms": 500.0,
                "agentic_consensus_latency_ms": 1000.0,
                "checks": {"agent_never_actuated": True},
                "aggregate": {"safe": True},
            }
            benign = {
                **ddos,
                "scenario": "benign",
                "classification": "TN",
                "authorized_domains": [],
                "claim_winner_domains": [],
                "would_execute_domains": [],
                "detection_latency_ms": None,
                "agentic_consensus_latency_ms": None,
            }
            for case_id, payload in (("01-ddos", ddos), ("01-benign", benign)):
                case_dir = root / case_id
                case_dir.mkdir()
                (case_dir / "authority-summary.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                (case_dir / "benchmark-exit-code.txt").write_text(
                    "0\n", encoding="utf-8"
                )
                (case_dir / "evaluator-exit-code.txt").write_text(
                    "0\n", encoding="utf-8"
                )

            report = evaluate_authority_campaign(root)
            self.assertTrue(report["aggregate"]["promotion_ready"])
            self.assertEqual(report["metrics"]["TP"], 1)
            self.assertEqual(report["metrics"]["TN"], 1)
            self.assertEqual(report["metrics"]["f1"], 1.0)

            benign["authorized_domains"] = ["domain-0"]
            (root / "01-benign" / "authority-summary.json").write_text(
                json.dumps(benign), encoding="utf-8"
            )
            unsafe = evaluate_authority_campaign(root)
            self.assertFalse(unsafe["aggregate"]["promotion_ready"])
            self.assertFalse(unsafe["checks"]["all_benign_rejected"])

    def test_agentic_run_is_invalid_when_agents_or_decisions_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "inactive-agentic-ddos"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-dry-run",
                "scenario": "ddos",
                "flow": "10.0.0.1->10.0.0.8",
                "controller_sets": 2,
                "agentic_shadow": True,
            }), encoding="utf-8")
            (run_dir / "attack_start_ns.txt").write_text(
                "1000000000\n", encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            for name in ("ping_before.txt", "ping_after.txt"):
                (run_dir / name).write_text(
                    "3 packets transmitted, 3 received, 0% packet loss\n",
                    encoding="utf-8",
                )
            self.write_iperf(run_dir / "baseline.json", 1_000_000)
            self.write_iperf(run_dir / "attack.json", 100_000_000)
            rows = [
                {
                    "sampled_ns": 1_500_000_000,
                    "port": str(6060 + index),
                    "status": {"cid": f"domain-{index}"},
                    "agentic": {
                        "requested": True,
                        "active": False,
                        "mode": "shadow",
                        "authoritative": False,
                        "cid": f"domain-{index}",
                        "decisions": [],
                    },
                    "anomalies": ([{
                        "anomaly_id": "attack-a",
                        "kind": "THROUGHPUT_SPIKE",
                        "ts_detect_ns": 1_500_000_000,
                        "mitigation": {
                            "attempted": False,
                            "executed": False,
                            "reason": "aguardando decisão colaborativa",
                        },
                    }] if index == 0 else []),
                    "collaboration": {"decisions": []},
                }
                for index in range(2)
            ]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            summary = summarize_run(run_dir)

            self.assertEqual(summary["classification"], "INVALID")
            self.assertEqual(summary["agentic_active_domains"], [])
            self.assertIn(
                "agentes shadow ativos em 0/2 domínio(s)",
                summary["invalid_reasons"],
            )
            self.assertIn(
                "anomalia de ataque sem decisão registrada pelos agentes shadow",
                summary["invalid_reasons"],
            )

            # Se Holt não detectar nada, ausência de negociação é um FN real,
            # não uma medição inválida: o agente só recebe candidatos anômalos.
            rows[0]["anomalies"] = []
            for row in rows:
                row["agentic"]["active"] = True
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            no_detection = summarize_run(run_dir)
            self.assertEqual(no_detection["classification"], "FN")
            self.assertEqual(no_detection["invalid_reasons"], [])

    def test_live_mitigation_failure_is_invalid_with_real_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "failed-live"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-live",
                "scenario": "ddos",
                "flow": "10.0.0.1->10.0.0.8",
            }), encoding="utf-8")
            (run_dir / "attack_start_ns.txt").write_text(
                "1000000000\n", encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            for name in ("ping_before.txt", "ping_after.txt"):
                (run_dir / name).write_text(
                    "3 packets transmitted, 3 received, 0% packet loss\n",
                    encoding="utf-8",
                )
            self.write_iperf(run_dir / "baseline.json", 1_000_000)
            self.write_iperf(run_dir / "attack.json", 100_000_000)
            row = {
                "sampled_ns": 2_100_000_000,
                "status": {"cid": "domain-0"},
                "anomalies": [{
                    "anomaly_id": "a1",
                    "kind": "THROUGHPUT_SPIKE",
                    "ts_detect_ns": 1_500_000_000,
                    "mitigation": {
                        "attempted": False,
                        "executed": False,
                        "reason": "aguardando decisão colaborativa",
                    },
                }],
                "collaboration": {"decisions": [{
                    "flow": "10.0.0.1->10.0.0.8",
                    "decision": "MITIGATE",
                    "score": 0.95,
                    "confirming_domains": ["domain-0", "domain-1"],
                    "claim": {
                        "coordinator": "domain-0",
                        "claimed_ns": 2_000_000_000,
                        "won": True,
                    },
                    "mitigation": {
                        "attempted": True,
                        "executed": False,
                        "reason": "FlowBlocker HTTP 404",
                    },
                }]},
            }
            (run_dir / "timeline.ndjson").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )

            summary = summarize_run(run_dir)

            self.assertEqual(summary["classification"], "INVALID")
            self.assertTrue(summary["detected_attack"])
            self.assertEqual(summary["mitigation_reason"], "FlowBlocker HTTP 404")
            self.assertIn(
                "mitigação live não executada: FlowBlocker HTTP 404",
                summary["invalid_reasons"],
            )

    def test_summary_correlates_detection_claim_and_mitigation(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run-1"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-live",
                "scenario": "ddos",
                "flow": "10.0.0.1->10.0.0.8",
                "controller_sets": 2,
                "agentic_shadow": True,
            }), encoding="utf-8")
            (run_dir / "attack_start_ns.txt").write_text(
                "1000000000\n", encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            (run_dir / "ping_before.txt").write_text(
                "3 packets transmitted, 3 received, 0% packet loss\n",
                encoding="utf-8",
            )
            (run_dir / "ping_after.txt").write_text(
                "5 packets transmitted, 0 received, 100% packet loss\n",
                encoding="utf-8",
            )
            self.write_iperf(run_dir / "baseline.json", 1_000_000)
            self.write_iperf(run_dir / "attack.json", 100_000_000)
            (run_dir / "initial-agent-6061.json").write_text(json.dumps({
                "cid": "domain-1", "waiting_events": 1,
                "expired_proposals": 0,
            }), encoding="utf-8")
            (run_dir / "initial-agent-6060.json").write_text(json.dumps({
                "cid": "domain-0", "waiting_events": 1,
                "expired_proposals": 1,
            }), encoding="utf-8")
            row = {
                "sampled_ns": 2_100_000_000,
                "port": "6061",
                "status": {"cid": "domain-1"},
                "anomalies": [{
                    "anomaly_id": "a1",
                    "kind": "THROUGHPUT_SPIKE",
                    "ts_detect_ns": 1_500_000_000,
                    "mitigation": {"attempted": True, "executed": True,
                                   "reason": "FlowBlocker HTTP 200"},
                }],
                "collaboration": {"decisions": [{
                    "flow": "10.0.0.1->10.0.0.8",
                    "decision": "MITIGATE",
                    "score": 0.95,
                    "confirming_domains": ["domain-0", "domain-1"],
                    "claim": {"coordinator": "domain-1",
                              "claimed_ns": 2_000_000_000, "won": True},
                    "mitigation": {"attempted": True, "executed": True,
                                   "reason": "FlowBlocker HTTP 200"},
                }]},
                "agentic": {
                    "requested": True,
                    "active": True,
                    "mode": "shadow",
                    "authoritative": False,
                    "cid": "domain-1",
                    "decisions": [],
                    "waiting_events": 1,
                    "expired_proposals": 0,
                    "decision_events": [{
                        "flow": "10.0.0.1->10.0.0.8",
                        "decision": "AGREED",
                        "event_id": "domain-1:agreement-1",
                        "evaluated_ns": 2_000_000_000,
                        "state_entered_ns": 2_000_000_000,
                        "first_proposal_ns": 1_600_000_000,
                        "last_proposal_ns": 1_800_000_000,
                        "required_votes": 2,
                        "proposals": [
                            {"cid": "domain-0", "created_ns": 1_600_000_000},
                            {"cid": "domain-1", "created_ns": 1_800_000_000},
                        ],
                        "mitigate_votes": ["domain-0", "domain-1"],
                        "legacy_comparison": {
                            "available": True, "matches": True,
                        },
                    }],
                },
            }
            peer_row = {
                "sampled_ns": 2_100_000_000,
                "port": "6060",
                "status": {"cid": "domain-0"},
                "anomalies": [],
                "collaboration": {"decisions": []},
                "agentic": {
                    "requested": True,
                    "active": True,
                    "mode": "shadow",
                    "authoritative": False,
                    "cid": "domain-0",
                    "decisions": [],
                    "decision_events": [],
                    "waiting_events": 2,
                    "expired_proposals": 3,
                },
            }
            (run_dir / "timeline.ndjson").write_text(
                json.dumps(row) + "\n" + json.dumps(peer_row) + "\n",
                encoding="utf-8",
            )

            summary = summarize_run(run_dir)

            self.assertEqual(summary["decisions"], ["MITIGATE"])
            self.assertEqual(summary["coordinator"], "domain-1")
            self.assertEqual(summary["detection_latency_ms"], 500.0)
            self.assertEqual(summary["consensus_latency_ms"], 500.0)
            self.assertEqual(summary["baseline_spike_anomalies"], 0)
            self.assertEqual(summary["attack_spike_anomalies"], 1)
            self.assertEqual(summary["ping_after_loss_percent"], 100.0)
            self.assertTrue(summary["mitigation_executed"])
            self.assertEqual(summary["classification"], "TP")
            self.assertEqual(summary["agentic_decisions"], ["AGREED"])
            self.assertEqual(
                summary["agentic_active_domains"], ["domain-0", "domain-1"]
            )
            self.assertEqual(
                summary["agentic_mitigate_votes"], ["domain-0", "domain-1"]
            )
            self.assertTrue(summary["agentic_matches_mcda"])
            self.assertTrue(summary["agentic_agent_agreement"])
            self.assertEqual(summary["agentic_first_proposal_latency_ms"], 100.0)
            self.assertEqual(
                summary["agentic_proposal_collection_latency_ms"], 200.0
            )
            self.assertEqual(summary["agentic_deliberation_latency_ms"], 200.0)
            self.assertEqual(summary["agentic_consensus_latency_ms"], 500.0)
            self.assertEqual(summary["agentic_required_votes"], 2)
            self.assertTrue(summary["agentic_quorum_reached"])
            self.assertEqual(summary["agentic_proposal_timestamps_ns"], {
                "domain-0": 1_600_000_000,
                "domain-1": 1_800_000_000,
            })
            self.assertEqual(
                summary["agentic_attack_to_consensus_latency_ms"], 1000.0
            )
            self.assertEqual(summary["agentic_waiting_events"], 1)
            self.assertEqual(summary["agentic_expired_proposals"], 2)
            metrics = aggregate_metrics([summary])
            self.assertEqual(metrics["f1"], 1.0)
            self.assertEqual(metrics["agentic"]["agreed_runs"], 1)
            self.assertEqual(
                metrics["agentic"]["agent_to_agent_agreement_rate"], 1.0
            )
            self.assertEqual(
                metrics["agentic"]["agent_to_mcda_agreement_rate"], 1.0
            )
            table = markdown_table([summary])
            self.assertIn("collaborative-live", table)
            self.assertIn("agentic: AGREED=1/1", table)

    def test_live_drop_may_interrupt_iperf_when_execution_and_loss_are_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "successful-live-disruption"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-live",
                "scenario": "ddos",
                "flow": "10.0.0.1->10.0.0.8",
            }), encoding="utf-8")
            (run_dir / "attack_start_ns.txt").write_text(
                "1000000000\n", encoding="utf-8"
            )
            (run_dir / "workload_status.json").write_text(json.dumps({
                "valid": True,
                "expect_disruption": True,
                "attack_disrupted": True,
                "attack_exit_code": 1,
                "attack_bps": None,
            }), encoding="utf-8")
            (run_dir / "ping_before.txt").write_text(
                "3 packets transmitted, 3 received, 0% packet loss\n",
                encoding="utf-8",
            )
            (run_dir / "ping_after.txt").write_text(
                "5 packets transmitted, 0 received, 100% packet loss\n",
                encoding="utf-8",
            )
            self.write_iperf(run_dir / "baseline.json", 1_000_000)
            row = {
                "sampled_ns": 2_100_000_000,
                "status": {"cid": "domain-0"},
                "anomalies": [{
                    "anomaly_id": "attack",
                    "kind": "THROUGHPUT_SPIKE",
                    "ts_detect_ns": 1_500_000_000,
                    "mitigation": {
                        "attempted": True,
                        "executed": True,
                        "reason": "FlowBlocker HTTP 200",
                    },
                }],
                "collaboration": {"decisions": [{
                    "flow": "10.0.0.1->10.0.0.8",
                    "decision": "MITIGATE",
                    "score": 0.95,
                    "confirming_domains": ["domain-0", "domain-1"],
                    "claim": {
                        "coordinator": "domain-0",
                        "claimed_ns": 2_000_000_000,
                        "won": True,
                    },
                    "mitigation": {
                        "attempted": True,
                        "executed": True,
                        "reason": "FlowBlocker HTTP 200",
                    },
                }]},
            }
            (run_dir / "timeline.ndjson").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )

            summary = summarize_run(run_dir)

            self.assertEqual(summary["classification"], "TP")
            self.assertTrue(summary["attack_disrupted"])
            self.assertTrue(summary["mitigation_executed"])
            self.assertEqual(summary["ping_after_loss_percent"], 100.0)
            self.assertEqual(summary["invalid_reasons"], [])

            (run_dir / "ping_after.txt").write_text(
                "5 packets transmitted, 5 received, 0% packet loss\n",
                encoding="utf-8",
            )
            no_loss = summarize_run(run_dir)
            self.assertEqual(no_loss["classification"], "INVALID")
            self.assertIn(
                "FlowBlocker confirmou execução, mas o ping não observou perda",
                no_loss["invalid_reasons"],
            )

            (run_dir / "ping_after.txt").write_text(
                "5 packets transmitted, 0 received, 100% packet loss\n",
                encoding="utf-8",
            )
            row["anomalies"][0]["mitigation"]["executed"] = False
            row["anomalies"][0]["mitigation"]["reason"] = "FlowBlocker HTTP 500"
            row["collaboration"]["decisions"][0]["mitigation"]["executed"] = False
            row["collaboration"]["decisions"][0]["mitigation"]["reason"] = (
                "FlowBlocker HTTP 500"
            )
            (run_dir / "timeline.ndjson").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )
            unconfirmed = summarize_run(run_dir)
            self.assertEqual(unconfirmed["classification"], "INVALID")
            self.assertIn(
                "iperf interrompido sem mitigação live confirmada",
                unconfirmed["invalid_reasons"],
            )

    def test_missing_traffic_is_invalid_instead_of_true_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "failed-benign"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-dry-run",
                "scenario": "benign",
                "flow": "10.0.0.1->10.0.0.8",
            }), encoding="utf-8")
            (run_dir / "workload_status.json").write_text(json.dumps({
                "valid": False,
                "reason": "switches sem conexão OpenFlow",
            }), encoding="utf-8")

            summary = summarize_run(run_dir)
            metrics = aggregate_metrics([summary])

            self.assertEqual(summary["classification"], "INVALID")
            self.assertFalse(summary["measurement_valid"])
            self.assertIn("switches sem conexão OpenFlow",
                          summary["invalid_reasons"])
            self.assertEqual(metrics["INVALID"], 1)
            self.assertEqual(metrics["TN"], 0)

    def test_pre_attack_spike_contaminates_run_without_negative_latency(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "contaminated-ddos"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "local-dry-run",
                "scenario": "ddos",
                "flow": "10.0.0.1->10.0.0.8",
            }), encoding="utf-8")
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            (run_dir / "attack_start_ns.txt").write_text(
                "2000000000\n", encoding="utf-8"
            )
            for name in ("ping_before.txt", "ping_after.txt"):
                (run_dir / name).write_text(
                    "3 packets transmitted, 3 received, 0% packet loss\n",
                    encoding="utf-8",
                )
            self.write_iperf(run_dir / "baseline.json", 1_000_000)
            self.write_iperf(run_dir / "attack.json", 100_000_000)
            rows = [
                {
                    "sampled_ns": 1_600_000_000,
                    "port": "6060",
                    "status": {"cid": "domain-0"},
                    "anomalies": [{
                        "anomaly_id": "baseline-fp",
                        "kind": "THROUGHPUT_SPIKE",
                        "ts_detect_ns": 1_500_000_000,
                        "mitigation": {"attempted": True, "executed": False},
                    }],
                    "collaboration": {"decisions": []},
                },
                {
                    "sampled_ns": 2_600_000_000,
                    "port": "6060",
                    "status": {"cid": "domain-0"},
                    "anomalies": [{
                        "anomaly_id": "attack-tp",
                        "kind": "THROUGHPUT_SPIKE",
                        "ts_detect_ns": 2_500_000_000,
                        "mitigation": {"attempted": True, "executed": False},
                    }],
                    "collaboration": {"decisions": []},
                },
            ]
            (run_dir / "timeline.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            summary = summarize_run(run_dir)
            metrics = aggregate_metrics([summary])

            self.assertEqual(summary["classification"], "CONTAMINATED")
            self.assertEqual(summary["baseline_spike_anomalies"], 1)
            self.assertEqual(summary["attack_spike_anomalies"], 1)
            self.assertEqual(summary["detection_latency_ms"], 500.0)
            self.assertEqual(summary["baseline_action_domains"], ["domain-0"])
            self.assertEqual(summary["action_domains"], ["domain-0"])
            self.assertEqual(metrics["CONTAMINATED"], 1)
            self.assertEqual(metrics["TP"], 0)

    def test_collaborative_benign_drop_does_not_become_ddos_false_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "benign-drop"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(json.dumps({
                "mode": "collaborative-dry-run",
                "scenario": "benign",
                "flow": "10.0.0.1->10.0.0.8",
            }), encoding="utf-8")
            (run_dir / "workload_status.json").write_text(
                json.dumps({"valid": True}), encoding="utf-8"
            )
            for name in ("ping_before.txt", "ping_after.txt"):
                (run_dir / name).write_text(
                    "3 packets transmitted, 3 received, 0% packet loss\n",
                    encoding="utf-8",
                )
            self.write_iperf(run_dir / "baseline.json", 1_000_000)
            (run_dir / "timeline.ndjson").write_text(json.dumps({
                "sampled_ns": 2_000_000_000,
                "port": "6061",
                "status": {"cid": "domain-1"},
                "anomalies": [{
                    "anomaly_id": "normal-flow-end",
                    "kind": "THROUGHPUT_DROP",
                    "ts_detect_ns": 1_500_000_000,
                    "mitigation": {"attempted": False, "executed": False},
                }],
                "collaboration": {"decisions": []},
            }) + "\n", encoding="utf-8")

            summary = summarize_run(run_dir)

            self.assertEqual(summary["classification"], "TN")
            self.assertEqual(summary["drop_anomalies"], 1)
            self.assertEqual(summary["spike_anomalies"], 0)


if __name__ == "__main__":
    unittest.main()
