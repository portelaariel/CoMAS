"""Isolated experimental predictive agents; never a DDoS/actuation authority.

The online model consumes current/past telemetry only. A bounded-time pair of
two explicit observations of s2--s3 is corroboration, not independent votes or
proof that the SLA can be protected. Old frozen experiments are not changed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from typing import Any, Dict

from qos_damped_holt import MultiHorizonDampedHoltForecaster
from sla_risk import SLA_RISK_EVENT_TYPE, SlaRiskPersistence, SlaRiskPolicy, evaluate_sla_forecast


SCHEMA = "comas-predictive-sla-shadow/1"
SUBJECT = {"type": "link", "id": "mininet:s2:4--s3:3"}
TIMING = dict(max_sample_age_s=5, sample_interval_tolerance_s=0.5,
              max_pair_skew_s=2, api_poll_s=0.5, request_timeout_s=1, safety_poll_s=2)
BOUNDARY = dict(mode="experimental_predictive_sidecars_shadow",
                ddos_agents_modified=False, authority_request=False,
                actuator_request=False, llm_consulted=False, authorized=False,
                promotion_eligible=False, deployment_eligible=False)


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def positive_ns(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("timestamp inválido")
    return value


def finite(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        raise ValueError("valor numérico inválido")
    return float(value)


class OnlineRiskAgent:
    """One local series/state, with resets instead of zero-filled gaps.

    Publication freshness is observation-based, not extended by a late retry.
    Inactive entry is gated exactly as v4; an existing forecast alert still
    renews above the current threshold, but that is NOT a preventive vote.
    """

    def __init__(self, model, subject: Dict[str, Any], settings: Dict[str, Any]):
        self.model, self.subject, self.settings = model, dict(subject), dict(settings)
        self.policy = SlaRiskPolicy(metric=model.metric, comparator="MAX", threshold=settings["threshold"],
                                   horizons_steps=tuple(h.horizon_steps for h in model.horizons),
                                   required_consecutive_horizons=settings["required_consecutive_horizons"])
        self.last_seen_ns = None
        self.last_sample_digest = None
        self.last_valid_ns = None
        self.generation = 0
        self.reset()

    def reset(self) -> None:
        self.forecaster = MultiHorizonDampedHoltForecaster(self.model)
        self.persistence = SlaRiskPersistence(self.settings["activation_windows"], self.settings["clear_windows"])
        self.active = False
        self.last_valid_ns = None
        self.count = 0
        self.generation += 1

    def ingest(self, sample: Dict[str, Any], now_ns: int) -> Dict[str, Any] | None:
        """Duplicate polls do not become additional model observations."""
        positive_ns(now_ns)
        if not isinstance(sample, dict):
            self.reset()
            raise ValueError("amostra QoS inválida")
        try:
            timestamp = positive_ns(sample.get("ts_ns"))
            if (sample.get("schema_version") != 1 or sample.get("cid") != self.subject["cid"]
                    or sample.get("port_id") != self.subject["port_id"]
                    or finite(sample.get("capacity_bps")) != self.subject["capacity_bps"]
                    or f"{sample.get('dpid')}:{sample.get('port_no')}" != self.subject["port_id"]):
                raise ValueError("identidade/capacidade da amostra incompatível")
            if not 0 <= now_ns - timestamp <= TIMING["max_sample_age_s"] * 1e9:
                raise ValueError("amostra antiga/futura")
            content_digest = digest(sample)
            if timestamp == self.last_seen_ns:
                if content_digest != self.last_sample_digest:
                    raise ValueError("conteúdo mudou sob o mesmo timestamp")
                return None
            if self.last_seen_ns is not None and timestamp < self.last_seen_ns:
                raise ValueError("amostra retrocedeu no tempo")
            self.last_seen_ns, self.last_sample_digest = timestamp, content_digest
            if sample.get("valid") is not True or sample.get("quality") != "VALID":
                self.reset()
                return self._record(sample, "INVALID_QUALITY", None)
            value = finite(sample.get("utilization_ratio"))
            interval = finite(sample.get("interval_s"))
            if value < 0 or abs(interval - self.model.sample_interval_s) > TIMING["sample_interval_tolerance_s"]:
                self.reset()
                return self._record(sample, "INVALID_INTERVAL", None)
            reset_reason = None
            if (self.last_valid_ns is not None
                    and abs((timestamp - self.last_valid_ns) / 1e9 - self.model.sample_interval_s)
                    > TIMING["sample_interval_tolerance_s"]):
                self.reset()
                reset_reason = "MISSED_OR_IRREGULAR_SAMPLE"
            self.last_valid_ns = timestamp
            self.count += 1
            forecasts = self.forecaster.update(value)
            if not forecasts:
                result = self._record(sample, "PRIMING", None)
                result["reset_reason"] = reset_reason
                return result
            evaluation = evaluate_sla_forecast(
                policy=self.policy, cid=self.subject["cid"], subject_type="port", subject_id=self.subject["port_id"],
                observed_value=value, window_id=self.count, observation_ns=timestamp,
                sample_interval_s=self.model.sample_interval_s, forecasts=forecasts,
                model_id=self.model.resolved_model_id(), model_type=self.model.model_type,
                created_ns=now_ns, ttl_s=TIMING["max_sample_age_s"])
            # Unlike the generic certificate TTL, usable evidence expires from
            # observation time. A delayed publication cannot renew old telemetry.
            evaluation["expires_ns"] = timestamp + int(TIMING["max_sample_age_s"] * 1e9)
            candidate = evaluation["decision"] == SLA_RISK_EVENT_TYPE
            breached = value >= self.policy.threshold
            inhibit = candidate and breached and not self.active
            state = self.persistence.update({**evaluation, "decision": "WATCH" if inhibit else evaluation["decision"]})
            self.active = state["active"]
            result = self._record(sample, "FORECAST_READY", evaluation)
            result.update(candidate=candidate, active=self.active, activation=state["transitioned"] and self.active,
                          clear_transition=state["transitioned"] and not self.active,
                          entry_inhibited=inhibit, threshold_breach=breached, reset_reason=reset_reason)
            return result
        except (ValueError, TypeError, KeyError):
            self.reset()
            raise

    def _record(self, sample, status, evaluation):
        return dict(status=status, sample=copy.deepcopy(sample), evaluation=evaluation,
                    generation=self.generation, observations_in_generation=self.count,
                    candidate=False, active=False, activation=False, clear_transition=False,
                    entry_inhibited=False, threshold_breach=None)


def vote(record: Dict[str, Any]) -> tuple:
    if record["status"] != "FORECAST_READY":
        return "ABSTAIN", record["status"]
    if record["threshold_breach"]:
        return "OBSERVE", "CURRENT_THRESHOLD_BREACH_NOT_PREVENTION"
    if record["candidate"] and record["active"]:
        return "PREVENT", "FRESH_ACTIVE_BELOW_THRESHOLD_FORECAST"
    return "OBSERVE", "NO_FRESH_ACTIVE_CANDIDATE"


def envelope(config, run_id, record, completed_ns):
    timestamp = record["sample"]["ts_ns"]
    return dict(schema_version=SCHEMA, kind="RISK", config_sha256=config["config_sha256"],
                run_id=run_id, subject=SUBJECT, cid=record["sample"]["cid"],
                port_id=record["sample"]["port_id"], model_sha256=config["model"]["sha256"],
                model_id=config["model"]["model_id"], policy=config["policy"],
                observed_ns=timestamp, expires_ns=timestamp + int(TIMING["max_sample_age_s"] * 1e9),
                processing_completed_ns=completed_ns,
                forecast_available_ns=completed_ns if record["status"] == "FORECAST_READY" else None,
                record=record, boundary=BOUNDARY)


def proposal(config, risk, publication_ack_ns, evaluated_ns):
    decision, reason = vote(risk["record"])
    return dict(schema_version=SCHEMA, kind="PROPOSAL", config_sha256=config["config_sha256"],
                run_id=risk["run_id"], subject=SUBJECT, cid=risk["cid"], port_id=risk["port_id"],
                risk_sha256=digest(risk), observed_ns=risk["observed_ns"], expires_ns=risk["expires_ns"],
                risk_publication_ack_ns=publication_ack_ns, evaluated_ns=evaluated_ns,
                decision=decision, reason=reason, boundary=BOUNDARY)


def verify_pair(config, run_id, subject, risk, item, now_ns):
    """Structural provenance is not authentication or independent truth."""
    for payload, kind in ((risk, "RISK"), (item, "PROPOSAL")):
        if not isinstance(payload, dict):
            raise ValueError("risco/proposta ausente")
        expected = dict(schema_version=SCHEMA, kind=kind, config_sha256=config["config_sha256"],
                        run_id=run_id, subject=SUBJECT, cid=subject["cid"], port_id=subject["port_id"], boundary=BOUNDARY)
        if any(payload.get(k) != v for k, v in expected.items()):
            raise ValueError("contrato/binding de risco/proposta incompatível")
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
            <= positive_ns(item["risk_publication_ack_ns"]) <= positive_ns(item["evaluated_ns"]) <= now_ns):
        raise ValueError("timestamps de disponibilidade fora de ordem")
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
        points = [finite(h["predicted_value"]) for h in horizons]
        candidate = any(point >= config["policy"]["threshold"] for point in points)
        if (record["candidate"] is not candidate or record["threshold_breach"] is not (value >= config["policy"]["threshold"])
                or (record["candidate"] and evaluation["decision"] != SLA_RISK_EVENT_TYPE)):
            raise ValueError("candidato não corresponde aos pontos publicados")
        # Recheck the stateless forecast contract, not an independent model
        # judgment or reconstruction of the sender's persistence history.
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


def consensus(config, run_id, values, now_ns):
    """Latest committed pair, same mapped link and bounded observation skew.

    This is a new shadow prototype, not the existing CoMAS DDoS quorum or its
    authority gate. It never releases authorization, even with two PREVENTs.
    """
    result = dict(status="WAITING_PROPOSALS", reason="MISSING_DOMAIN", authorized=False,
                  authority_requested=False, actuation_requested=False, decisions={}, evidence_sha256={})
    observations = []
    for subject in config["subjects"]:
        cid = subject["cid"]
        risk, item = values.get(f"risks/{cid}"), values.get(f"proposals/{cid}")
        if risk is None or item is None:
            return result
        try:
            verify_pair(config, run_id, subject, risk, item, now_ns)
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            return {**result, "status": "INSUFFICIENT_EVIDENCE", "reason": str(exc)}
        observations.append(item["observed_ns"])
        result["decisions"][cid] = item["decision"]
        result["evidence_sha256"][cid] = digest(item)
    if max(observations) - min(observations) > TIMING["max_pair_skew_s"] * 1e9:
        return {**result, "status": "INSUFFICIENT_EVIDENCE", "reason": "OBSERVATION_TIME_SKEW"}
    votes = set(result["decisions"].values())
    status = ("SHADOW_PREVENT_AGREED" if votes == {"PREVENT"} else "OBSERVE" if votes == {"OBSERVE"}
              else "INSUFFICIENT_EVIDENCE" if "ABSTAIN" in votes else "DISAGREED")
    return {**result, "status": status, "reason": "BOUNDED_TIME_PAIR_NOT_INDEPENDENT_VOTES",
            "observation_skew_ms": (max(observations) - min(observations)) / 1e6}
