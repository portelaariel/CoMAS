import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_shadow_report as report
import predictive_sla_shadow_diagnostics as diagnostic
import predictive_sla_validation as provenance
import test_predictive_sla_shadow_ramp as fixtures
from test_predictive_sla_validation import create_case
from qos_damped_holt import QosDampedHoltModel


class ManifestInputTests(unittest.TestCase):
    def test_non_object_manifest_is_rejected_without_traceback(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text("[]")
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(report.main(["build", "--manifest", str(path)]), 2)
            self.assertIn("schema/checksum inválido", stderr.getvalue())

    def test_explicit_extra_without_receipt_is_unknown_even_with_partial_runtime_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            name = report.PREFIXES[0] + "unfinalized"
            root = results / name
            (root / "pilot").mkdir(parents=True)
            (root / "protocol.json").write_text("partial protocol, not validated")
            (root / "pilot" / "shadow.log").write_text("worker may have started\n")
            entry = report.entries_for(results, [name])[-1]
            self.assertEqual(entry["expected_receipt_status"], "MISSING_FINAL_RECEIPT")
            self.assertIsNone(entry["profile"])
            self.assertEqual(report.load_attempt(entry), (None, None, None))
            self.assertEqual(len(report.inventory([entry])), 2)

    def test_receipt_appearing_cannot_silently_reclassify_unfinalized_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            name = report.PREFIXES[0] + "late-receipt"
            root = results / name
            (root / "pilot").mkdir(parents=True)
            entry = report.entries_for(results, [name])[-1]
            (root / "pilot" / "pilot-run.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "sem recibo mudou"):
                report.load_attempt(entry)

    def test_present_but_invalid_receipt_is_not_downgraded_to_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            name = report.PREFIXES[0] + "invalid-receipt"
            root = results / name
            (root / "pilot").mkdir(parents=True)
            (root / "protocol.json").write_text(json.dumps(dict(case=dict(profile="slow-ramp"))))
            (root / "pilot" / "pilot-run.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "schema/checksum inválido"):
                report.entries_for(results, [name])


class OfflineConsolidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Source(fixtures.FrozenRampTests):
            pass
        cls.source_fixture = Source
        Source.setUpClass()
        cls.addClassCleanup(Source.tearDownClass)
        cls.results = Source.source.parent.parent
        cls.contexts = {}
        for ordinal, (profile, rep, status, name) in enumerate(report.COHORT):
            cls.make_attempt(profile, rep, status, name, ordinal)
        cls.template_root = cls.results / (report.OUTPUT_PREFIX + "template")
        cls.template = report.freeze(cls.results, cls.template_root)

    @classmethod
    def make_attempt(cls, profile, rep, status, name, ordinal):
        root = cls.results / name
        module = report.MODULES[profile]
        args = (cls.source_fixture.source, cls.source_fixture.idle, root)
        p = module.freeze(*args, profile) if module is report.controls else module.freeze(*args)
        native = create_case(p, p["case"], root / "pilot", ordinal=ordinal)
        native.rename(root / "pilot" / "workload")
        native = root / "pilot" / "workload"
        record_path = native / "run.json"
        record = json.loads(record_path.read_text())
        record.update(cleanup_errors=[], process_return_codes_after_cleanup=[-2, -2])
        provenance.write_new_json(native / "collection-note.json", {"synthetic_fixture": True})
        record_path.write_text(json.dumps(provenance.seal(record, "run_sha256")))
        series, record, _ = provenance._read_case(p, p["case"], native)
        config = diagnostic.load_config(root / "shadow-config.json")
        model = QosDampedHoltModel.load(root / "model.json")
        run_id = f"{ordinal+1:032x}"
        values = [.2, .2] + series[0]["values"] + [.2] * 4
        with patch.object(fixtures, "RUN_ID", run_id):
            _, _, journals = fixtures.traces(values, config=config, model=model,
                base_ns=series[0]["timestamps_ns"][0] - 4_000_000_000, domain_offset=.001)
        shadow = root / "runs" / run_id
        shadow.mkdir(parents=True)
        shadow_start = record["started_ns"] - 6_000_000_000
        provenance.write_new_json(shadow / "manifest.json", dict(config_sha256=config["config_sha256"],
            started_ns=shadow_start, duration_s=p["shadow_duration_s"]))
        for cid, rows in journals.items():
            (shadow / f"{cid}.ndjson").write_text("".join(json.dumps(row) + "\n" for row in rows))
            (shadow / f"{cid}-transport.ndjson").write_text('{"kind":"synthetic_fixture"}\n')
            provenance.write_new_json(shadow / f"{cid}-summary.json", dict(status="COMPLETED"))
        (shadow / "preflight-transport.ndjson").write_text('{"kind":"synthetic_fixture"}\n')
        pid = 12345 + ordinal
        (shadow / "launcher-transport.ndjson").write_text(json.dumps(dict(kind="synthetic_fixture", pid=pid)) + "\n")
        summary = dict(schema_version=diagnostic.SUMMARY_SCHEMA, status="COMPLETED",
            originals_unchanged=True, diagnostic_traces_complete=True, boundary=p["boundary"],
            artifacts_sha256={path.name: provenance.digest_file(path) for path in shadow.iterdir()})
        if status == "STOPPED_ERROR":
            summary.update(status="STOPPED_ERROR", diagnostic_traces_complete=False, failed_stage="workers",
                           domain_reports=[dict(cid=p["subjects"][0]["cid"], status="STOPPED_ERROR", error="timed out")])
        provenance.write_new_json(shadow / "shadow-summary.json", summary)
        receipt = provenance.seal(dict(schema_version=module.RECEIPT_SCHEMA, status=status,
            protocol_sha256=p["protocol_sha256"], boundary=p["boundary"], originals_unchanged=True,
            source_errors=[], cleanup_errors=[], shadow_exit_code=0 if status == "COLLECTED" else 2,
            collector_exit_code=0, shadow_launcher_pid=pid, started_ns=shadow_start - 1,
            ended_ns=shadow_start + int(p["shadow_duration_s"] * 1e9) + 3_000_000_000,
            error=None if status == "COLLECTED" else "diagnóstico shadow falhou", shadow_run=str(shadow)), "run_sha256")
        provenance.write_new_json(root / "pilot" / "pilot-run.json", receipt)
        (root / "pilot" / "shadow.log").write_text("synthetic fixture; not a real experiment\n")
        if status == "COLLECTED":
            result = module.evaluate(root / "protocol.json", receipt)
            filename = "control-observation.json" if module is report.controls else "paired-timing.json"
            provenance.write_new_json(root / "pilot" / filename, result)
        cls.contexts[name] = (p, receipt, series, record, journals)
        return root

    def manifest(self, suffix):
        root = self.results / (report.OUTPUT_PREFIX + suffix)
        root.mkdir()
        path = root / "manifest.json"
        provenance.write_new_json(path, self.template)
        return path

    def change_file(self, path, contents):
        original = path.read_bytes()
        self.addCleanup(path.write_bytes, original)
        path.write_bytes(contents)

    def test_full_offline_replay_keeps_twelve_pilots_and_known_failure_without_network(self):
        path = self.manifest("complete")
        before = report.inventory(self.template["entries"])
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")), \
                patch.object(report.slow.subprocess, "Popen", side_effect=AssertionError("runtime command")), \
                patch.object(report.slow.collector, "preflight", side_effect=AssertionError("preflight")):
            result = report.build(path)
        self.assertEqual(result["status"], "CONSOLIDATED")
        self.assertEqual((result["attempts_total"], result["completed_pilots"], result["stopped_attempts"]), (13, 12, 1))
        self.assertTrue(result["originals_unchanged"])
        self.assertTrue(result["original_reports_reproduced"])
        self.assertEqual(report.inventory(self.template["entries"]), before)
        self.assertEqual(result["original_v4_status"], "NOT_PASSED")
        self.assertIsNone(result["false_alarm_rate"])
        self.assertIsNone(result["specificity"])
        self.assertFalse(result["statistical_independence_established"])
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["sla_protection_established"])
        for profile in report.MODULES:
            self.assertEqual(result["profiles"][profile]["completed_pilots"], 3)
            self.assertEqual(result["profiles"][profile]["correlated_port_series"], 6)
        failure = next(row for row in result["attempts"] if row["status"] == "STOPPED_ERROR")
        self.assertIsNone(failure["domains"])
        self.assertIsNone(failure["failure"]["performance_metrics"])
        self.assertEqual(failure["failure"]["root_cause"], "NOT_ESTABLISHED")
        self.assertEqual(failure["failure"]["domain_reports"][0]["error"], "timed out")
        self.assertNotIn("counters", failure["failure"]["domain_reports"][0])
        self.assertTrue((path.parent / "source-inventory.json").is_file())
        md = (path.parent / "validation-summary.md").read_text()
        self.assertIn(failure["directory"], md)
        self.assertIn("NOT_PASSED", md)
        self.assertIn("não é aprovação", md)
        self.assertIn("NOT_ESTABLISHED", md)
        for attempt in result["attempts"]:
            if attempt.get("pulse_evidence") is not None:
                self.assertEqual(len(attempt["pulse_evidence"]), 2)
                self.assertTrue(all(len(d["pulses"]) == 4 for d in attempt["pulse_evidence"]))
                self.assertTrue(all(p["windows_count"] > 0 for d in attempt["pulse_evidence"] for p in d["pulses"]))
                self.assertGreater(max(p["peak_mean_utilization"] for d in attempt["pulse_evidence"] for p in d["pulses"]), 1)

    def test_required_failed_attempt_cannot_be_omitted_even_with_resealed_manifest(self):
        path = self.manifest("omit-failure")
        changed = copy.deepcopy(self.template)
        changed["entries"] = [row for row in changed["entries"] if row["expected_receipt_status"] != "STOPPED_ERROR"]
        path.write_text(json.dumps(provenance.seal(changed, "manifest_sha256")))
        with self.assertRaises(ValueError):
            report.build(path)
        self.assertFalse((path.parent / "validation-summary.json").exists())

    def test_changed_source_file_is_detected_before_consolidation(self):
        path = self.manifest("changed-file")
        source = Path(self.template["entries"][0]["root"]) / "pilot" / "shadow.log"
        self.change_file(source, source.read_bytes() + b"changed\n")
        with self.assertRaisesRegex(ValueError, "origem mudaram"):
            report.build(path)

    def test_resealed_altered_result_still_fails_exact_offline_replay(self):
        path = self.manifest("false-result")
        source = Path(self.template["entries"][0]["root"]) / "pilot" / "paired-timing.json"
        altered = report.read_json(source)
        altered["originals_unchanged"] = False
        self.change_file(source, json.dumps(provenance.seal(altered, "report_sha256")).encode())
        changed = copy.deepcopy(self.template)
        changed["source_files_sha256"][str(source)] = provenance.digest_file(source)
        path.write_text(json.dumps(provenance.seal(changed, "manifest_sha256")))
        with self.assertRaisesRegex(ValueError, "reproduzível"):
            report.build(path)

    def test_duplicate_root_or_changed_policy_cannot_redefine_cohort(self):
        for index, update in enumerate((lambda m: m["entries"][1].update(root=m["entries"][0]["root"]),
                                        lambda m: m["policy"].update(action="promote"))):
            path = self.manifest("cohort-tamper-" + str(index))
            changed = copy.deepcopy(self.template)
            update(changed)
            path.write_text(json.dumps(provenance.seal(changed, "manifest_sha256")))
            with self.assertRaises(ValueError):
                report.load_manifest(path)

    def test_new_candidate_directory_cannot_be_silently_ignored(self):
        root = self.results / (report.PREFIXES[0] + "unregistered")
        root.mkdir()
        self.addCleanup(root.rmdir)
        with self.assertRaisesRegex(ValueError, "adicionais"):
            report.freeze(self.results, self.results / (report.OUTPUT_PREFIX + "unlisted"))

    def test_additional_failed_attempt_is_explicitly_registered_and_retained(self):
        name = report.PREFIXES[2] + "extra-receipt"
        root = self.make_attempt("stable-low", None, "STOPPED_ERROR", name, 14)
        self.addCleanup(shutil.rmtree, root)
        unknown_names = [report.PREFIXES[0] + suffix for suffix in ("empty-extra", "partial-extra")]
        for unknown_name in unknown_names:
            unknown_root = self.results / unknown_name
            unknown_root.mkdir()
            self.addCleanup(shutil.rmtree, unknown_root)
        partial_file = self.results / unknown_names[1] / "partial.log"
        partial_file.write_text("unsealed and incomplete runtime evidence\n")
        destination = self.results / (report.OUTPUT_PREFIX + "registered")
        manifest = report.freeze(self.results, destination, [name, *unknown_names])
        self.assertEqual(len(manifest["entries"]), 16)
        result = report.build(destination / "manifest.json")
        self.assertEqual(result["status"], "CONSOLIDATED_WITH_UNFINALIZED_SOURCES")
        self.assertEqual(result["registered_directories"], 16)
        self.assertEqual(result["attempts_total"], 14)
        self.assertEqual(result["completed_pilots"], 12)
        self.assertEqual(result["stopped_attempts"], 2)
        self.assertEqual(result["unfinalized_directories"], 2)
        self.assertEqual(result["profiles"]["stable-low"]["stopped_attempts"], 2)
        self.assertEqual(sum(p["attempts"] for p in result["profiles"].values()), 14)
        self.assertEqual(sum(p["correlated_port_series"] for p in result["profiles"].values()), 24)
        self.assertEqual(partial_file.read_text(), "unsealed and incomplete runtime evidence\n")
        for source in result["unfinalized_sources"]:
            self.assertEqual(source["status"], "UNKNOWN")
            self.assertIsNone(source["profile"])
            self.assertIsNone(source["domains"])
            self.assertIsNone(source["execution_started"])
            self.assertIsNone(source["execution_completed"])
            self.assertIsNone(source["authority"])
            self.assertIsNone(source["actuation"])
            self.assertIsNone(source["performance_metrics"])
            self.assertEqual(source["protocol_validation"], "NOT_ASSESSED")
        self.assertIn(str(partial_file), result["source_files_sha256"])
        md = (destination / "validation-summary.md").read_text()
        self.assertIn("Ausência de recibo não prova ausência de execução", md)
        self.assertTrue(all(name in md for name in unknown_names))
        partial_file.write_text("changed after freezing")
        with self.assertRaisesRegex(ValueError, "origem mudaram"):
            report.load_manifest(destination / "manifest.json")

    def test_existing_output_is_never_overwritten(self):
        path = self.manifest("existing-output")
        output = path.parent / "validation-summary.md"
        output.write_text("preserve me")
        with self.assertRaisesRegex(ValueError, "saída já existe"):
            report.build(path)
        self.assertEqual(output.read_text(), "preserve me")
        with self.assertRaises(ValueError):
            report.freeze(self.results, path.parent)

    def test_overlapping_attempts_are_rejected_not_counted_as_separate_repetitions(self):
        first = self.contexts[report.COHORT[0][3]][1]
        original = report.load_attempt
        def overlapping(entry):
            module, p, receipt = original(entry)
            if entry == self.template["entries"][1]:
                receipt = dict(receipt, started_ns=first["started_ns"] + 1,
                               ended_ns=first["ended_ns"] - 1)
            return module, p, receipt
        with patch.object(report, "load_attempt", side_effect=overlapping), self.assertRaisesRegex(ValueError, "sobrepostas"):
            report.consolidate(self.template)

    def test_reused_shadow_uuid_is_rejected_before_replaying_foreign_run(self):
        first = Path(self.contexts[report.COHORT[0][3]][1]["shadow_run"]).name
        original = report.load_attempt
        def duplicated(entry):
            module, p, receipt = original(entry)
            if entry == self.template["entries"][1]:
                receipt = dict(receipt, shadow_run=str(Path(entry["root"]) / "runs" / first))
            return module, p, receipt
        with patch.object(report, "load_attempt", side_effect=duplicated), self.assertRaisesRegex(ValueError, "UUID"):
            report.consolidate(self.template)

    def test_symlink_inside_source_is_rejected(self):
        source = Path(self.template["entries"][0]["root"])
        link = source / "unexpected-link"
        link.symlink_to(source / "model.json")
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(ValueError, "link simbólico"):
            report.load_manifest(self.manifest("symlink"))

    def test_pulse_window_cannot_be_invented_when_interval_metadata_is_missing(self):
        name = next(row[3] for row in report.COHORT if row[0] == "short-pulses")
        p, _, series, native, journals = self.contexts[name]
        changed = copy.deepcopy(journals)
        sample = next(row["record"]["sample"] for row in changed[p["subjects"][0]["cid"]]
            if row["kind"] == "LOCAL_EVALUATION" and row["record"]["sample"]["ts_ns"] == series[0]["timestamps_ns"][0])
        sample["interval_s"] = None
        with self.assertRaisesRegex(ValueError, "intervalo medido"):
            report.pulse_evidence(p, series, native, changed)

    def test_source_change_during_build_prevents_writing_summary(self):
        path = self.manifest("late-source-change")
        source = Path(self.template["entries"][0]["root"]) / "pilot" / "shadow.log"
        original_bytes = source.read_bytes()
        self.addCleanup(source.write_bytes, original_bytes)
        original = report.consolidate
        def changed(manifest):
            result = original(manifest)
            source.write_bytes(original_bytes + b"late change\n")
            return result
        with patch.object(report, "consolidate", side_effect=changed), self.assertRaisesRegex(ValueError, "origem mudaram"):
            report.build(path)
        self.assertFalse((path.parent / "validation-summary.json").exists())

    def test_cli_requires_explicit_commands_and_has_no_traffic_optin(self):
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
            report.main(["run", "--allow-lab-traffic"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
