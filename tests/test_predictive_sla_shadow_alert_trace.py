import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_shadow_alert_trace as trace
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_validation as provenance
import test_predictive_sla_shadow_ramp as fixtures
import test_predictive_sla_shadow_report as report_fixtures


VALUES = fixtures.old.WARNING_VALUES + [.76, .77, .78, .79] + [.2] * 20
LATER_PEER = [.2] * 11 + [.4, .6, .7, .75, .76, .77, .78] + [.2] * 20


def rebuild_consensus(config, journals):
    subjects = config["subjects"]
    pairs = {s["cid"]: [e for e in journals[s["cid"]] if e["kind"] == "PAIR_PUBLICATION"] for s in subjects}
    for cid in journals:
        journals[cid] = [e for e in journals[cid] if e["kind"] != "SHADOW_CONSENSUS"]
    for index in range(min(map(len, pairs.values()))):
        snapshot = dict(values={}, mod_revisions={}, snapshot_revision=2*(index+1))
        for subject in subjects:
            pair = pairs[subject["cid"]][index]
            for kind, value in (("risks", pair["risk"]), ("proposals", pair["proposal"])):
                key = f"{kind}/{subject['cid']}"
                snapshot["values"][key] = copy.deepcopy(value)
                snapshot["mod_revisions"][key] = pair["pair_mod_revision"]
        received = pairs[subjects[0]["cid"]][index]["risk"]["observed_ns"] + 31_000_000
        assessment = protocol.consensus(config, fixtures.RUN_ID, snapshot, received)
        for subject in subjects:
            journals[subject["cid"]].append(dict(kind="SHADOW_CONSENSUS", cid=subject["cid"],
                assessment=copy.deepcopy(assessment), peer_snapshot=copy.deepcopy(snapshot),
                peer_snapshot_received_ns=received, consensus_completed_ns=received+1000))


def fixture(values=VALUES, peer=None):
    config, series, journals = fixtures.traces(values)
    if peer is not None:
        _, other_series, other_journals = fixtures.traces(peer)
        cid = config["subjects"][1]["cid"]
        series[1], journals[cid] = other_series[1], other_journals[cid]
    rebuild_consensus(config, journals)
    return config, series, journals


class RecordedLifecycleTests(unittest.TestCase):
    def analyze(self, data):
        config, series, journals = data
        return trace.analyze(config, fixtures.RUN_ID, series, journals, config["subjects"][0]["cid"], 13)

    def test_initial_disagreement_does_not_hide_agreements_on_renewals(self):
        result = self.analyze(fixture(peer=LATER_PEER))
        self.assertEqual(result["status"], "TRACED")
        self.assertEqual(result["target"]["reason"], "no_sustained_episode_within_horizon")
        self.assertEqual(result["initial_pair_joint_witnesses"], 0)
        self.assertGreater(result["renewal_joint_witnesses"], 0)
        self.assertGreater(result["joint_classification_counts_for_target_port"]["NO_SUSTAINED_EPISODE_WITHIN_HORIZON"], 0)
        self.assertEqual(set(result["activation_pair"]["assessment_status_counts"]), {"DISAGREED"})
        self.assertFalse(result["causal_filtering_established"])

    def test_disagreed_full_cycle_is_a_recorded_negative_not_proof_of_filtering(self):
        result = self.analyze(fixture(peer=[.2]*len(VALUES)))
        self.assertEqual(result["status"], "TRACED")
        self.assertEqual(result["distinct_joint_witnesses"], 0)
        self.assertEqual(result["lifecycle"]["end_reason"], "CLEAR_RECORDED")
        self.assertFalse(result["causal_filtering_established"])
        self.assertIsNone(result["target"]["matched_episode_id"])
        self.assertFalse(result["boundary"]["authority_request"])

    def test_duplicate_observers_do_not_double_count_joint_witnesses(self):
        result = self.analyze(fixture())
        raw = sum(row["assessment"]["status"] == "SHADOW_PREVENT_AGREED" for row in result["consensus_observations"])
        self.assertEqual(raw, result["distinct_joint_witnesses"]*2)
        self.assertTrue(all(w["classifications"] for w in result["joint_witnesses"]))

    def test_later_renewal_can_anticipate_a_different_supported_episode(self):
        values = fixtures.old.WARNING_VALUES + [.76]*6 + [.9]*4 + [.2]*20
        peer = [.2]*11 + [.4, .6, .7, .75] + [.76]*5 + [.9]*4 + [.2]*20
        result = self.analyze(fixture(values, peer))
        self.assertEqual(result["target"]["reason"], "no_sustained_episode_within_horizon")
        self.assertEqual(result["initial_pair_joint_witnesses"], 0)
        self.assertGreater(result["renewal_joint_witnesses"], 0)
        self.assertGreater(result["joint_classification_counts_for_target_port"]["PRE_SAMPLED_ONSET"], 0)
        self.assertNotIn("NO_SUSTAINED_EPISODE_WITHIN_HORIZON", result["joint_classification_counts_for_target_port"])

    def test_post_clear_observer_receipt_for_member_pair_is_not_discarded(self):
        config, series, journals = fixture(fixtures.old.WARNING_VALUES + [.2]*20)
        target_ts = fixtures.BASE + 13*2_000_000_000
        clear_ts = fixtures.BASE + 15*2_000_000_000
        for cid, events in journals.items():
            for event in events:
                if event["kind"] == "SHADOW_CONSENSUS" and event["peer_snapshot"]["values"][f"risks/{cid}"]["observed_ns"] == target_ts:
                    event.update(peer_snapshot_received_ns=clear_ts+2_000_000,
                                 consensus_completed_ns=clear_ts+2_001_000)
            local = [e for e in events if e["kind"] != "SHADOW_CONSENSUS"]
            views = sorted((e for e in events if e["kind"] == "SHADOW_CONSENSUS"), key=lambda e: e["consensus_completed_ns"])
            journals[cid] = local + views
        result = self.analyze((config, series, journals))
        self.assertEqual(result["initial_pair_joint_witnesses"], 1)
        self.assertGreater(result["joint_witnesses"][0]["consensus_completed_ns"], clear_ts)

    def test_generation_change_is_not_mistaken_for_clear_or_merged_with_renewals(self):
        config, series, journals = fixture(peer=[.2]*len(VALUES))
        cid = config["subjects"][0]["cid"]
        cutoff = fixtures.BASE + 14*2_000_000_000
        for event in journals[cid]:
            if event["kind"] == "LOCAL_EVALUATION" and event["record"]["sample"]["ts_ns"] >= cutoff:
                event["record"]["generation"] += 1
            elif event["kind"] == "PAIR_PUBLICATION" and event["risk"]["observed_ns"] >= cutoff:
                event["risk"]["record"]["generation"] += 1
                event["proposal"] = protocol.proposal(config, event["risk"], event["proposal"]["evaluated_ns"])
        rebuild_consensus(config, journals)
        result = self.analyze((config, series, journals))
        self.assertEqual(result["status"], "TRACED_WITH_INCOMPLETE_COVERAGE")
        self.assertEqual(result["lifecycle"]["end_reason"], "GENERATION_CHANGED_WITHOUT_CLEAR")
        self.assertEqual(result["lifecycle"]["renewals"], 0)

    def test_next_activation_after_clear_is_not_merged_with_target_lifecycle(self):
        config, series, journals = fixture(VALUES + VALUES)
        result = self.analyze((config, series, journals))
        terminal = result["lifecycle"]["terminal_record"]["sample"]["ts_ns"]
        self.assertTrue(all(p["observed_ns"] < terminal for p in result["renewal_pairs"]))
        later = [e for e in journals[config["subjects"][0]["cid"]] if e["kind"] == "LOCAL_EVALUATION"
                 and e["record"]["activation"] and e["record"]["sample"]["ts_ns"] > terminal]
        self.assertTrue(later)

    def test_no_clear_or_missing_native_sample_keeps_coverage_incomplete(self):
        config, series, journals = fixture(peer=[.2]*len(VALUES))
        cutoff = fixtures.BASE + 14*2_000_000_000
        truncated = {cid: [e for e in events if (e["record"]["sample"]["ts_ns"] if e["kind"] == "LOCAL_EVALUATION"
            else e["risk"]["observed_ns"] if e["kind"] == "PAIR_PUBLICATION" else e["peer_snapshot_received_ns"]) <= cutoff]
            for cid, events in journals.items()}
        result = self.analyze((config, series, truncated))
        self.assertEqual(result["status"], "TRACED_WITH_INCOMPLETE_COVERAGE")
        self.assertEqual(result["lifecycle"]["end_reason"], "JOURNAL_ENDED_WITHOUT_CLEAR")

        cid = config["subjects"][0]["cid"]
        for key, events in journals.items():
            journals[key] = [e for e in events if (e["record"]["sample"]["ts_ns"] if e["kind"] == "LOCAL_EVALUATION"
                else e["risk"]["observed_ns"] if e["kind"] == "PAIR_PUBLICATION" else
                e["peer_snapshot"]["values"][f"risks/{cid}"]["observed_ns"]) != cutoff]
        result = self.analyze((config, series, journals))
        self.assertEqual(result["status"], "TRACED_WITH_INCOMPLETE_COVERAGE")
        self.assertIn(cutoff, result["lifecycle"]["native_samples_not_seen"])

    def test_unseen_renewal_is_not_treated_as_a_successful_negative(self):
        config, series, journals = fixture(peer=[.2]*len(VALUES))
        ts = fixtures.BASE + 14*2_000_000_000
        for cid, events in journals.items():
            journals[cid] = [e for e in events if not (e["kind"] == "SHADOW_CONSENSUS"
                and e["peer_snapshot"]["values"][f"risks/{config['subjects'][0]['cid']}"]["observed_ns"] == ts)]
        result = self.analyze((config, series, journals))
        self.assertEqual(result["status"], "TRACED_WITH_INCOMPLETE_COVERAGE")
        self.assertTrue(result["lifecycle"]["pairs_without_valid_bound_assessment"])

    def test_only_indeterminate_peer_evidence_does_not_establish_complete_negative(self):
        config, series, journals = fixture(peer=[.2]*len(VALUES))
        local_cid, peer_cid = [s["cid"] for s in config["subjects"]]
        stale = next(e for e in journals[peer_cid] if e["kind"] == "PAIR_PUBLICATION")
        for events in journals.values():
            for event in events:
                if event["kind"] != "SHADOW_CONSENSUS":
                    continue
                snapshot = event["peer_snapshot"]
                if not snapshot["values"][f"risks/{local_cid}"]["record"]["active"]:
                    continue
                for kind, value in (("risks", stale["risk"]), ("proposals", stale["proposal"])):
                    snapshot["values"][f"{kind}/{peer_cid}"] = copy.deepcopy(value)
                    snapshot["mod_revisions"][f"{kind}/{peer_cid}"] = stale["pair_mod_revision"]
                event["assessment"] = protocol.consensus(config, fixtures.RUN_ID, snapshot, event["peer_snapshot_received_ns"])
        result = self.analyze((config, series, journals))
        self.assertEqual(result["status"], "TRACED_WITH_INCOMPLETE_COVERAGE")
        self.assertFalse(result["lifecycle"]["pairs_without_valid_bound_assessment"])
        self.assertTrue(result["lifecycle"]["pairs_with_only_indeterminate_assessments"])

    def test_clear_without_observer_followup_to_pair_expiry_is_incomplete(self):
        config, series, journals = fixture(fixtures.old.WARNING_VALUES + [.2]*20)
        clear_ts = fixtures.BASE + 15*2_000_000_000
        for cid, events in journals.items():
            journals[cid] = [e for e in events if e["kind"] != "SHADOW_CONSENSUS"
                or e["consensus_completed_ns"] <= clear_ts+32_000_000]
        result = self.analyze((config, series, journals))
        self.assertEqual(result["lifecycle"]["end_reason"], "CLEAR_RECORDED")
        self.assertEqual(result["status"], "TRACED_WITH_INCOMPLETE_COVERAGE")
        self.assertEqual(len(result["lifecycle"]["observers_without_pair_expiry_followup"]), 2)

    def test_fabricated_disagreement_is_rejected_even_without_an_agreement_to_validate(self):
        config, series, journals = fixture()
        for events in journals.values():
            for event in events:
                if event["kind"] == "SHADOW_CONSENSUS" and event["assessment"]["status"] == "SHADOW_PREVENT_AGREED":
                    event["assessment"]["status"] = "DISAGREED"
        with self.assertRaisesRegex(ValueError, "consenso não reproduzível"):
            self.analyze((config, series, journals))

    def test_absent_activation_or_domain_and_foreign_publication_are_rejected(self):
        config, series, journals = fixture()
        for cid, index in (("foreign", 13), (config["subjects"][0]["cid"], 0)):
            with self.assertRaises(ValueError):
                trace.analyze(config, fixtures.RUN_ID, series, journals, cid, index)
        pair = next(e for e in journals[config["subjects"][0]["cid"]] if e["kind"] == "PAIR_PUBLICATION")
        pair["commit_outcome"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            self.analyze((config, series, journals))


class OfflineBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Source(fixtures.FrozenRampTests):
            pass
        Source.setUpClass()
        cls.addClassCleanup(Source.tearDownClass)
        class Owner:
            source_fixture, contexts = Source, {}
            results = Source.source.parent.parent
        cls.root = report_fixtures.OfflineConsolidationTests.make_attempt.__func__(
            Owner, "slow-ramp", 1, "COLLECTED", trace.cohort.COHORT[0][3], 0)
        cls.path = cls.root / "protocol.json"
        cls.original_path = cls.root / "pilot" / "paired-timing.json"
        original = trace.cohort.read_json(cls.original_path)
        cls.cid = original["domains"][0]["cid"]
        cls.index = original["domains"][0]["strict_activation_episodes"]["activations"][0]["activation_index"]

    def destination(self, suffix):
        return self.root.parent / (trace.OUTPUT_PREFIX + suffix)

    def test_build_replays_original_and_preserves_all_source_files_without_network(self):
        before = trace.cohort.inventory([dict(root=str(self.root))])
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")), \
                patch.object(fixtures.pilot.subprocess, "Popen", side_effect=AssertionError("runtime")), \
                patch.object(fixtures.pilot.collector, "preflight", side_effect=AssertionError("preflight")):
            result = trace.build(self.path, self.cid, self.index, self.destination("complete"))
        self.assertTrue(result["originals_unchanged"])
        self.assertTrue(result["original_report_reproduced"])
        self.assertEqual(result["source_files_sha256"], before)
        self.assertEqual(trace.cohort.inventory([dict(root=str(self.root))]), before)
        self.assertEqual(result["original_v4_status"], "NOT_PASSED")
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["report_execution"]["actuation"])
        self.assertEqual(result, provenance.seal(result, "report_sha256"))
        self.assertIn("não são alarmes", (self.destination("complete") / "alert-trace.md").read_text())

    def test_source_change_during_analysis_prevents_output(self):
        artifact = self.root / "pilot" / "shadow.log"
        content = artifact.read_bytes()
        self.addCleanup(artifact.write_bytes, content)
        real = trace.analyze
        def changed(*args):
            result = real(*args)
            artifact.write_bytes(content + b"changed\n")
            return result
        output = self.destination("late-change")
        with patch.object(trace, "analyze", side_effect=changed), self.assertRaisesRegex(ValueError, "fontes/código mudaram"):
            trace.build(self.path, self.cid, self.index, output)
        self.assertFalse(output.exists())

    def test_existing_output_or_original_report_cannot_be_overwritten(self):
        output = self.destination("existing")
        output.mkdir()
        (output / "preserved").write_text("keep")
        for destination in (output, self.root, self.original_path.parent):
            with self.assertRaises(ValueError):
                trace.build(self.path, self.cid, self.index, destination)
        self.assertEqual((output / "preserved").read_text(), "keep")

    def test_resealed_modified_original_report_cannot_be_used_as_evidence(self):
        content = self.original_path.read_bytes()
        self.addCleanup(self.original_path.write_bytes, content)
        original = trace.cohort.read_json(self.original_path)
        original["measurement_status"] = "changed"
        self.original_path.write_text(json.dumps(provenance.seal(original, "report_sha256")))
        output = self.destination("changed-original")
        with self.assertRaisesRegex(ValueError, "relatório original não reproduzido"):
            trace.build(self.path, self.cid, self.index, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
