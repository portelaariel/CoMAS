"""Atomic, per-domain publication contract for the isolated shadow v2 pilot.

Reuse the frozen v1 forecasting/persistence implementation without editing it.
Commit metadata comes from a single ETCD range response, not from peer claims.
An atomic pair is not a global two-domain transaction or authorization.
"""

from __future__ import annotations

import copy

import predictive_sla_shadow_protocol as v1
from sla_risk import SLA_RISK_EVENT_TYPE, SlaRiskPolicy, evaluate_sla_forecast


SCHEMA = "comas-predictive-sla-shadow/2"
SUBJECT = copy.deepcopy(v1.SUBJECT)
TIMING = copy.deepcopy(v1.TIMING)
BOUNDARY = copy.deepcopy(v1.BOUNDARY)
PUBLICATION = dict(
    method="etcd_v3_atomic_pair_transaction",
    atomic_scope="one_domain_risk_and_proposal_not_all_domains",
    reader_proof="same_positive_mod_revision_in_one_range_snapshot",
    ack_policy="client_observed_pair_ack_only_in_post_response_journal",
    timeout_policy="stop_without_retry_commit_outcome_unknown",
)
OnlineRiskAgent = v1.OnlineRiskAgent
encoded, digest, positive_ns, finite, vote = v1.encoded, v1.digest, v1.positive_ns, v1.finite, v1.vote


def envelope(config, run_id, record, completed_ns):
    risk = v1.envelope(config, run_id, record, completed_ns)
    risk.update(schema_version=SCHEMA, publication_method=PUBLICATION["method"])
    return risk


def proposal(config, risk, evaluated_ns):
    """A vote is prepared before the joint commit; no precommit ack is invented."""
    decision, reason = vote(risk["record"])
    return dict(schema_version=SCHEMA, kind="PROPOSAL", config_sha256=config["config_sha256"],
                run_id=risk["run_id"], subject=SUBJECT, cid=risk["cid"], port_id=risk["port_id"],
                risk_sha256=digest(risk), observed_ns=risk["observed_ns"], expires_ns=risk["expires_ns"],
                evaluated_ns=evaluated_ns, decision=decision, reason=reason, boundary=BOUNDARY,
                publication_method=PUBLICATION["method"])


def verify_pair(config, run_id, subject, risk, item, now_ns):
    """Check the preserved forecast contract and new precommit timestamp order."""
    positive_ns(now_ns)
    for payload, kind in ((risk, "RISK"), (item, "PROPOSAL")):
        if not isinstance(payload, dict):
            raise ValueError("risco/proposta ausente")
        expected = dict(schema_version=SCHEMA, kind=kind, config_sha256=config["config_sha256"],
                        run_id=run_id, subject=SUBJECT, cid=subject["cid"], port_id=subject["port_id"],
                        boundary=BOUNDARY, publication_method=PUBLICATION["method"])
        if any(payload.get(k) != value for k, value in expected.items()):
            raise ValueError("contrato/binding de risco/proposta incompatível")
        # Actual acks/revisions cannot be known when constructing a txn value.
        if any(k in payload for k in ("risk_publication_ack_ns", "pair_publication_ack_ns", "mod_revision")):
            raise ValueError("confirmação de commit não pertence ao payload pré-publicação")
        observed = positive_ns(payload.get("observed_ns"))
        if (not 0 <= now_ns - observed <= TIMING["max_sample_age_s"] * 1e9
                or payload.get("expires_ns") != observed + int(TIMING["max_sample_age_s"] * 1e9)
                or now_ns >= payload["expires_ns"]):
            raise ValueError("risco/proposta expirado ou futuro")
    if (item["risk_sha256"] != digest(risk) or item["observed_ns"] != risk["observed_ns"]
            or risk.get("model_sha256") != config["model"]["sha256"]
            or risk.get("model_id") != config["model"]["model_id"] or risk.get("policy") != config["policy"]):
        raise ValueError("proposta não corresponde ao risco/modelo/política publicados")
    if not (risk["observed_ns"] <= positive_ns(risk["processing_completed_ns"])
            <= positive_ns(item["evaluated_ns"]) <= now_ns):
        raise ValueError("timestamps de preparação fora de ordem")
    record = risk["record"]
    if (record["sample"]["cid"] != subject["cid"] or record["sample"]["port_id"] != subject["port_id"]
            or record["sample"]["ts_ns"] != risk["observed_ns"]
            or record["sample"]["capacity_bps"] != subject["capacity_bps"]):
        raise ValueError("amostra não corresponde ao binding")
    if record["status"] == "FORECAST_READY":
        if (record["sample"].get("valid") is not True or record["sample"].get("quality") != "VALID"
                or any(type(record[k]) is not bool for k in ("candidate", "active", "threshold_breach"))):
            raise ValueError("qualidade/estado de previsão inválido")
        evaluation = record["evaluation"]
        horizons = evaluation["forecast"]["horizons"]
        if ([h["horizon_steps"] for h in horizons] != [2, 4, 6]
                or evaluation["model"]["id"] != config["model"]["model_id"]
                or evaluation["observation"]["value"] != record["sample"]["utilization_ratio"]):
            raise ValueError("previsões/modelo/observação incompatíveis")
        value = finite(record["sample"]["utilization_ratio"])
        candidate = any(finite(h["predicted_value"]) >= config["policy"]["threshold"] for h in horizons)
        if (record["candidate"] is not candidate or record["threshold_breach"] is not (value >= config["policy"]["threshold"])
                or (record["candidate"] and evaluation["decision"] != SLA_RISK_EVENT_TYPE)):
            raise ValueError("candidato não corresponde aos pontos publicados")
        checked = evaluate_sla_forecast(
            policy=SlaRiskPolicy(metric="utilization_ratio", comparator="MAX", threshold=config["policy"]["threshold"],
                                 horizons_steps=(2, 4, 6), required_consecutive_horizons=1),
            cid=subject["cid"], subject_type="port", subject_id=subject["port_id"],
            observed_value=value, window_id=evaluation["observation"]["window_id"],
            observation_ns=risk["observed_ns"], sample_interval_s=2, forecasts=horizons,
            model_id=config["model"]["model_id"], model_type="damped_holt_qos_multihorizon",
            created_ns=evaluation["created_ns"], ttl_s=TIMING["max_sample_age_s"])
        checked["expires_ns"] = risk["expires_ns"]
        if (checked != evaluation
                or not risk["observed_ns"] <= evaluation["created_ns"] <= risk["processing_completed_ns"]
                or risk["forecast_available_ns"] != risk["processing_completed_ns"]):
            raise ValueError("contrato da previsão publicada inconsistente")
    elif record["status"] not in {"PRIMING", "INVALID_QUALITY", "INVALID_INTERVAL"}:
        raise ValueError("estado de telemetria desconhecido")
    elif risk.get("forecast_available_ns") is not None or record.get("evaluation") is not None:
        raise ValueError("priming/qualidade inválida não disponibilizam previsão")
    if (item["decision"], item["reason"]) != vote(record):
        raise ValueError("voto não corresponde à evidência")


def consensus(config, run_id, snapshot, now_ns):
    """Use per-key ETCD revisions as well as identity/hash/time checks."""
    result = dict(status="WAITING_PROPOSALS", reason="MISSING_DOMAIN", authorized=False,
                  authority_requested=False, actuation_requested=False, decisions={}, evidence_sha256={},
                  pair_mod_revisions={}, abstentions={})
    observations = []
    try:
        values, revisions = snapshot["values"], snapshot["mod_revisions"]
        snapshot_revision = positive_ns(snapshot["snapshot_revision"])
        for subject in config["subjects"]:
            cid = subject["cid"]
            risk_key, proposal_key = f"risks/{cid}", f"proposals/{cid}"
            risk, item = values.get(risk_key), values.get(proposal_key)
            if risk is None or item is None:
                return result
            risk_revision = positive_ns(revisions.get(risk_key))
            proposal_revision = positive_ns(revisions.get(proposal_key))
            if risk_revision != proposal_revision or risk_revision > snapshot_revision:
                raise ValueError("risco/proposta não têm a mesma revisão de commit ETCD")
            verify_pair(config, run_id, subject, risk, item, now_ns)
            observations.append(item["observed_ns"])
            result["pair_mod_revisions"][cid] = risk_revision
            result["decisions"][cid] = item["decision"]
            result["evidence_sha256"][cid] = digest(item)
            if item["decision"] == "ABSTAIN":
                result["abstentions"][cid] = item["reason"]
    except (ValueError, KeyError, TypeError, OverflowError, AttributeError) as exc:
        return {**result, "status": "INSUFFICIENT_EVIDENCE", "reason": str(exc)}
    if max(observations) - min(observations) > TIMING["max_pair_skew_s"] * 1e9:
        return {**result, "status": "INSUFFICIENT_EVIDENCE", "reason": "OBSERVATION_TIME_SKEW"}
    votes = set(result["decisions"].values())
    status = ("SHADOW_PREVENT_AGREED" if votes == {"PREVENT"} else "OBSERVE" if votes == {"OBSERVE"}
              else "INSUFFICIENT_EVIDENCE" if "ABSTAIN" in votes else "DISAGREED")
    return {**result, "status": status,
            "reason": "PREDICTION_UNAVAILABLE" if "ABSTAIN" in votes else "BOUNDED_TIME_PAIR_NOT_INDEPENDENT_VOTES",
            "observation_skew_ms": (max(observations) - min(observations)) / 1e6}
