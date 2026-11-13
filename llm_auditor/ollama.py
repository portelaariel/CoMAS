"""Cliente Ollama com saída estruturada e validação estrita."""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional


PROTOCOL_VALUES = ["CONSISTENT", "INCONSISTENT", "INSUFFICIENT_EVIDENCE"]
SCENARIO_VALUES = ["CORRECT", "INCORRECT", "UNKNOWN"]
STAGE_VALUES = ["FINAL", "INTERMEDIATE", "NO_DECISION"]
EXECUTION_VALUES = [
    "EXECUTED",
    "DRY_RUN_SUPPRESSED",
    "SKIPPED_OTHER_COORDINATOR",
    "FAILED",
    "NOT_REQUESTED",
    "UNKNOWN",
]
EFFECTIVENESS_VALUES = [
    "EFFECTIVE", "INEFFECTIVE", "NOT_APPLICABLE", "UNKNOWN"
]


EXPLANATION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "supporting_evidence": {
            "type": "array", "items": {"type": "string"}
        },
        "contradicting_evidence": {
            "type": "array", "items": {"type": "string"}
        },
        "missing_information": {
            "type": "array", "items": {"type": "string"}
        },
    },
    "required": [
        "summary", "supporting_evidence", "contradicting_evidence",
        "missing_information",
    ],
    "additionalProperties": False,
}


EVALUATION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "protocol_consistency": {
            "type": "string",
            "enum": PROTOCOL_VALUES,
            "description": (
                "Verifica se o estado observado respeita as regras do "
                "protocolo. Um estado intermediário válido com quórum ainda "
                "incompleto é CONSISTENT, não INCONSISTENT."
            ),
        },
        "scenario_correctness": {
            "type": "string", "enum": SCENARIO_VALUES
        },
        "decision_stage": {"type": "string", "enum": STAGE_VALUES},
        "execution_status": {
            "type": "string",
            "enum": EXECUTION_VALUES,
            "description": (
                "Status agregado do episódio. DRY_RUN_SUPPRESSED quando um "
                "vencedor do claim teria executado, mas authority-dry-run "
                "impediu a atuação; SKIPPED_OTHER_COORDINATOR quando uma "
                "decisão AGREED foi autorizada localmente, mas outro agente "
                "venceu o claim; NOT_REQUESTED somente quando nenhuma "
                "decisão solicitou execução local."
            ),
        },
        "operational_effectiveness": {
            "type": "string", "enum": EFFECTIVENESS_VALUES
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "summary": {"type": "string"},
        "supporting_evidence": {
            "type": "array", "items": {"type": "string"}
        },
        "contradicting_evidence": {
            "type": "array", "items": {"type": "string"}
        },
        "missing_information": {
            "type": "array", "items": {"type": "string"}
        },
    },
    "required": [
        "protocol_consistency", "scenario_correctness", "decision_stage",
        "execution_status", "operational_effectiveness", "confidence",
        "summary", "supporting_evidence", "contradicting_evidence",
        "missing_information",
    ],
    "additionalProperties": False,
}


class OllamaAuditError(RuntimeError):
    """Falha de transporte ou de contrato da resposta do Ollama."""


def _validate_schema(value: Any, schema: Dict[str, Any], path: str = "response") -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise OllamaAuditError(f"{path} deve ser objeto JSON")
        required = schema.get("required") or []
        missing = [key for key in required if key not in value]
        if missing:
            raise OllamaAuditError(f"{path} não contém campos: {missing}")
        properties = schema.get("properties") or {}
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise OllamaAuditError(f"{path} contém campos extras: {unknown}")
        for key, item in value.items():
            if key in properties:
                _validate_schema(item, properties[key], f"{path}.{key}")
    elif expected == "array":
        if not isinstance(value, list):
            raise OllamaAuditError(f"{path} deve ser lista JSON")
        item_schema = schema.get("items") or {}
        for index, item in enumerate(value):
            _validate_schema(item, item_schema, f"{path}[{index}]")
    elif expected == "string":
        if not isinstance(value, str):
            raise OllamaAuditError(f"{path} deve ser texto")
    elif expected == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise OllamaAuditError(f"{path} deve ser número")
        if not math.isfinite(value):
            raise OllamaAuditError(f"{path} deve ser finito")
        if "minimum" in schema and value < schema["minimum"]:
            raise OllamaAuditError(f"{path} abaixo do mínimo")
        if "maximum" in schema and value > schema["maximum"]:
            raise OllamaAuditError(f"{path} acima do máximo")
    if "enum" in schema and value not in schema["enum"]:
        raise OllamaAuditError(f"{path} possui valor inválido: {value!r}")


def _json_block(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def explanation_prompt(record: Dict[str, Any]) -> str:
    compact = {
        key: value for key, value in record.items()
        if key != "source_event_ids"
    }
    return (
        "Você é o componente de explicação de um auditor pós-experimento "
        "do CoMAS, um framework SDN de defesa DDoS multi-domínio. O veredito "
        "abaixo já foi calculado por regras determinísticas e é autoritativo. "
        "Não o altere nem reavalie. Explique de modo técnico e conciso, usando "
        "somente os fatos fornecidos. Em authority-dry-run, executed=false é "
        "deliberado e não representa falha. O vencedor do claim NÃO se "
        "absteve: ele foi selecionado e teria executado, mas o modo dry-run "
        "suprimiu a chamada ao FlowBlocker. Somente os agentes que não "
        "venceram o claim se abstiveram porque outro coordenador já havia "
        "sido eleito. Preserve os termos técnicos 'authority gate', 'claim', "
        "'dry-run' e 'FlowBlocker', sem traduzi-los. "
        "operational_effectiveness=NOT_APPLICABLE significa que a eficácia no "
        "plano de dados não foi testada. Retorne somente o JSON solicitado.\n\n"
        f"Registro auditado:\n{_json_block(compact)}"
    )


def evaluation_prompt(evidence: Dict[str, Any]) -> str:
    return (
        "Você é um avaliador experimental, não autoritativo, de decisões do "
        "CoMAS. Classifique separadamente consistência do protocolo, correção "
        "diante do cenário de laboratório, estágio da decisão, execução e "
        "eficácia operacional. Consistência significa que o estado e as ações "
        "observadas obedecem às regras do protocolo; não significa que o "
        "processo já terminou. WAITING_PROPOSALS é CONSISTENT quando existem "
        "domínios/propostas faltantes, o quórum ainda não foi atingido e não "
        "houve atuação. CORROBORATED também pode ser CONSISTENT abaixo do "
        "quórum. Use INCONSISTENT somente se um estado, transição ou ação "
        "violar os fatos ou um invariante do protocolo. AGREED é uma decisão "
        "final de consenso e não "
        "significa que a regra foi executada. Em authority-dry-run, a não "
        "execução é intencional e a eficácia operacional é NOT_APPLICABLE. O "
        "vencedor foi selecionado e teria executado, mas o dry-run suprimiu o "
        "FlowBlocker; somente os não vencedores se abstiveram por já existir "
        "outro coordenador. Classifique o status agregado do episódio usando "
        "estas regras, nesta ordem: EXECUTED se executed_events>0; FAILED se "
        "houve tentativa que falhou; DRY_RUN_SUPPRESSED se execution_mode é "
        "authority-dry-run, existe atomic_claim_winner_events>=1 e "
        "would_execute_events>=1, mas attempted_execution_events=0 e "
        "executed_events=0; SKIPPED_OTHER_COORDINATOR quando existe AGREED "
        "autorizado, o agente observado não venceu o claim e há evidência de "
        "que outro coordenador foi eleito; NOT_REQUESTED para estados "
        "intermediários e para decisões finais negativas, como VETOED ou "
        "NORMAL, que não solicitam mitigação; caso contrário, UNKNOWN. Uma "
        "decisão AGREED autorizada solicitou mitigação, portanto um não "
        "vencedor nunca deve ser classificado como NOT_REQUESTED. "
        "Use as seguintes regras de estágio: AGREED, VETOED e NORMAL são "
        "finais; SUSPECT, CORROBORATED e WAITING* são intermediários válidos. "
        "Para scenario_correctness, um estado intermediário é UNKNOWN; em "
        "um estado final, compare a decisão com laboratory_context: DDoS "
        "confirmado requer consenso de mitigação, tráfego benigno requer "
        "NORMAL e um cenário com política de whitelist requer VETOED. "
        "VETOED ou NORMAL válidos não solicitam mitigação e, portanto, usam "
        "execution_status=NOT_REQUESTED. A eficácia é NOT_APPLICABLE sempre "
        "que não houve execução no plano de dados, inclusive em dry-run, "
        "espera, veto, decisão NORMAL ou abstenção de um não vencedor. "
        "Não invente fatos e retorne somente o JSON solicitado.\n\n"
        f"Evidência normalizada:\n{_json_block(evidence)}"
    )


class OllamaAuditClient:
    """Cliente mínimo do endpoint ``/api/chat`` do Ollama."""

    def __init__(
        self,
        *,
        model: str = "qwen3.5:9b",
        base_url: str = "http://127.0.0.1:11434",
        temperature: float = 0.0,
        seed: int = 42,
        num_ctx: int = 4096,
        keep_alive: Any = 0,
        timeout_s: float = 600.0,
        opener: Optional[Callable[..., Any]] = None,
    ) -> None:
        if not model:
            raise ValueError("model não pode ser vazio")
        if not base_url:
            raise ValueError("base_url não pode ser vazia")
        if num_ctx <= 0:
            raise ValueError("num_ctx deve ser positivo")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = float(temperature)
        self.seed = int(seed)
        self.num_ctx = int(num_ctx)
        self.keep_alive = keep_alive
        self.timeout_s = float(timeout_s)
        self.opener = opener or urllib.request.urlopen

    def _chat(self, prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "think": False,
            "format": schema,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
                "num_predict": 600,
            },
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout_s) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise OllamaAuditError(
                f"falha ao consultar {self.base_url} com {self.model}: {exc}"
            ) from exc
        content = (body.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise OllamaAuditError("resposta do Ollama não contém message.content")
        try:
            result = json.loads(content)
        except (TypeError, ValueError) as exc:
            raise OllamaAuditError("message.content não é JSON válido") from exc
        _validate_schema(result, schema)
        return {
            "model": body.get("model") or self.model,
            "result": result,
            "metrics": {
                "total_duration_ns": body.get("total_duration"),
                "load_duration_ns": body.get("load_duration"),
                "prompt_eval_count": body.get("prompt_eval_count"),
                "eval_count": body.get("eval_count"),
            },
            "inference_parameters": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
                "keep_alive": self.keep_alive,
            },
        }

    def explain(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return self._chat(explanation_prompt(record), EXPLANATION_SCHEMA)

    def evaluate(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        return self._chat(evaluation_prompt(evidence), EVALUATION_SCHEMA)
