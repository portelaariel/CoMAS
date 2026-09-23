import ast
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RuntimeWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup_script = (ROOT / "eMSN_ENV/setup_env.sh").read_text(
            encoding="utf-8"
        )
        cls.emitter_source = (ROOT / "ryu_apps/emitter_cnsm.py").read_text(
            encoding="utf-8"
        )
        cls.benchmark_source = (
            ROOT / "scripts/run_collaborative_benchmark.sh"
        ).read_text(encoding="utf-8")
        cls.workload_source = (
            ROOT / "experiments/run_mininet_workload.py"
        ).read_text(encoding="utf-8")
        cls.mininet_source = (
            ROOT / "eMSN_ENV/setup_mininet.py"
        ).read_text(encoding="utf-8")
        cls.runtime_fault_source = (
            ROOT / "scripts/run_agentic_runtime_faults.sh"
        ).read_text(encoding="utf-8")
        cls.authority_campaign_source = (
            ROOT / "scripts/run_agentic_authority_campaign.sh"
        ).read_text(encoding="utf-8")
        cls.authority_live_source = (
            ROOT / "scripts/run_agentic_authority_live_canary.sh"
        ).read_text(encoding="utf-8")
        cls.authority_live_campaign_source = (
            ROOT / "scripts/run_agentic_authority_live_campaign.sh"
        ).read_text(encoding="utf-8")
        cls.authority_live_replication_source = (
            ROOT / "scripts/run_agentic_authority_live_replication.sh"
        ).read_text(encoding="utf-8")
        cls.dockerfile = (ROOT / "Dockerfile.flow_predictor").read_text(
            encoding="utf-8"
        )
        cls.monitor_source = (
            ROOT / "experiments/monitor_predictors.py"
        ).read_text(encoding="utf-8")

    def _block(self, start_marker, end_marker):
        start = self.setup_script.index(start_marker)
        end = self.setup_script.index(end_marker, start)
        return self.setup_script[start:end]

    def test_emitter_advertises_resolvable_flowblocker_peer_name(self):
        ryu_block = self._block("# Ryu Core", "# SimpleSwitch REST")
        flowblocker_block = self._block("# FlowBlocker", "# Connect FB")

        self.assertIn('-e FB_PEER_ID="flow-blocker-$i"', ryu_block)
        # FB_PEER_ID is consumed by the emitter inside ryu-core, not by the
        # FlowBlocker process itself.
        self.assertNotIn("FB_PEER_ID", flowblocker_block)

    def test_all_old_etcd_nodes_are_removed_before_first_new_node_starts(self):
        cluster_block = self._block(
            'log "Removing previous ETCD nodes"',
            "# Wait for at least one endpoint",
        )
        remove_call = cluster_block.index('docker_rm_if "etcd${j}"')
        removal_loop_end = cluster_block.index("done", remove_call)
        first_docker_run = cluster_block.index("sudo docker run")

        self.assertLess(removal_loop_end, first_docker_run)

    def test_emitter_learns_arp_requests_and_replies(self):
        tree = ast.parse(self.emitter_source)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_arp_source"
        )

        class FakeArp:
            def __init__(self, opcode):
                self.opcode = opcode
                self.src_ip = "10.0.0.8"

        class FakePacket:
            def __init__(self, opcode):
                self.value = FakeArp(opcode)

            def get_protocol(self, _protocol):
                return self.value

        namespace = {"arp": types.SimpleNamespace(arp=FakeArp)}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "emitter_cnsm.py", "exec"), namespace)
        eth = types.SimpleNamespace(src="00:00:00:00:00:08")

        self.assertEqual(
            namespace["_arp_source"](eth, FakePacket(1)),
            ("00:00:00:00:00:08", "10.0.0.8"),
        )
        self.assertEqual(
            namespace["_arp_source"](eth, FakePacket(2)),
            ("00:00:00:00:00:08", "10.0.0.8"),
        )

    def test_benchmark_builds_emitter_before_bootstrap_and_checks_hosts(self):
        build_ryu = self.benchmark_source.index(
            'sudo docker build -t "$RYU_IMG"'
        )
        bootstrap = self.benchmark_source.index(
            'bash "$PROJECT_ROOT/eMSN_ENV/setup_env.sh"'
        )
        self.assertLess(build_ryu, bootstrap)
        self.assertIn("--domain-table-url", self.benchmark_source)
        self.assertIn("--expect-disruption", self.benchmark_source)
        self.assertNotIn("time.sleep(2.0)", self.workload_source)
        self.assertIn("ping_reverse_discovery.txt", self.workload_source)
        self.assertIn("wait_for_domain_hosts(", self.workload_source)

    def test_agent_modules_and_endpoint_are_wired_into_runtime(self):
        self.assertIn("agent_protocol.py", self.dockerfile)
        self.assertIn("domain_agent.py", self.dockerfile)
        self.assertIn("qos_telemetry.py", self.dockerfile)
        self.assertIn('/predictor/agent', self.monitor_source)
        self.assertIn('"agentic": agentic', self.monitor_source)
        self.assertIn('PREDICTOR_AGENTIC_ENABLED="$AGENTIC"', self.benchmark_source)

    def test_runtime_fault_gate_uses_preflighted_published_openflow_ports(self):
        self.assertIn('MININET_CONTROLLER_HOST', self.mininet_source)
        self.assertIn('wait_tcp 127.0.0.1 "$controller_port"', self.runtime_fault_source)
        self.assertIn(
            'MININET_CONTROLLER_HOST=127.0.0.1', self.runtime_fault_source
        )
        run_episode = self.runtime_fault_source.split(
            "run_episode() {", 1
        )[1].split("run_episode missing-agent", 1)[0]
        self.assertNotIn("sudo mn -c", run_episode)
        self.assertIn('preflight_openflow "$name"', run_episode)

    def test_authority_campaign_is_isolated_and_cannot_enable_actuation(self):
        self.assertIn(
            "BENCHMARK_AGENTIC_MODE=authority-dry-run",
            self.authority_campaign_source,
        )
        self.assertIn(
            "BENCHMARK_BOOTSTRAP_ENV=true", self.authority_campaign_source
        )
        self.assertIn(
            "BENCHMARK_EXPORT_HISTORY=false", self.authority_campaign_source
        )
        self.assertIn(
            "collaborative-dry-run", self.authority_campaign_source
        )
        self.assertNotIn("collaborative-live", self.authority_campaign_source)

    def test_authority_live_canary_requires_opt_in_and_negative_control(self):
        self.assertIn(
            "--allow-agentic-mitigation", self.authority_live_source
        )
        self.assertIn("run_case benign", self.authority_live_source)
        self.assertIn("run_case ddos", self.authority_live_source)
        self.assertIn("promotion_ready == true", self.authority_live_source)
        self.assertIn("merge-base --is-ancestor", self.authority_live_source)
        self.assertIn("PROMOTION_MODEL", self.authority_live_source)
        self.assertIn("agentic-live", self.benchmark_source)
        self.assertIn(
            'PREDICTOR_AGENTIC_LIVE_ACTUATION="$AGENTIC_LIVE_ACTUATION"',
            self.benchmark_source,
        )

    def test_authority_live_campaign_is_guarded_per_flow(self):
        source = self.authority_live_campaign_source
        self.assertIn("--allow-agentic-mitigation", source)
        self.assertIn("promotion_ready == true", source)
        self.assertIn("canary_ready == true", source)
        self.assertIn("control_marker", source)
        self.assertIn('scenario" == "ddos"', source)
        self.assertIn("BENCHMARK_BOOTSTRAP_ENV=true", source)
        self.assertIn("agentic-live", source)
        self.assertIn("evaluate_agentic_live_campaign.py", source)
        self.assertIn("bounded-episode-window-v2", source)
        self.assertIn("MCDA_EPISODE_LOOKBACK_MS", source)
        self.assertIn("MCDA_MAX_PRECEDING_WINDOWS", source)
        self.assertIn("definição MCDA v2 congelada exige", source)

    def test_authority_live_replication_freezes_design_and_checks_preflight(self):
        source = self.authority_live_replication_source
        self.assertIn("--allow-agentic-mitigation", source)
        self.assertIn("campaign_ready == true", source)
        self.assertIn("operational_ready == true", source)
        self.assertIn("comparative_ready == true", source)
        self.assertIn("merge-base --is-ancestor", source)
        self.assertIn("diff --quiet --ignore-submodules", source)
        self.assertIn("AGENTIC_REPLICATION_MIN_FREE_MB", source)
        self.assertIn("AGENTIC_REPLICATION_REPETITIONS:-9", source)
        self.assertIn("AGENTIC_LIVE_CAMPAIGN_SOURCE_HOSTS=h1,h2,h3", source)
        self.assertIn("AGENTIC_LIVE_CAMPAIGN_ATTACK_RATES=50M,100M,150M", source)
        self.assertIn("evaluate_agentic_live_replication.py", source)
        self.assertIn("bounded-episode-window-v2", source)
        self.assertIn("definição MCDA v2 congelada exige", source)
        self.assertIn(
            "campanha piloto não usa a definição MCDA v2 congelada", source
        )
        self.assertIn(
            "AGENTIC_LIVE_CAMPAIGN_MCDA_EPISODE_LOOKBACK_MS", source
        )


if __name__ == "__main__":
    unittest.main()
