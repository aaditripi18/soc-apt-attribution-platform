"""The analyst assistant: questions about one investigation, answered by a
language model from that investigation's stored results (ADR-0022).

**What the model is given.** Not the logs: a compact digest built here from the
read model — the investigation's verdict and its reasons, the observed
techniques with counts and times, the attack chain, the closest behavioural
profiles and clusters, group-specific evidence, observables, mitigations. The
digest is built by :func:`build_digest` from the same stored records the pages
show, so the assistant can say nothing the console could not show.

**What it is told.** To answer only from that digest; to say so when the digest
does not contain the answer and name the page that would; never to call a Group
responsible unless the digest marks it identified; to describe overlap as
similarity. The instructions are a constraint on wording, not a guarantee: a
language model can still be wrong, and the console says the answer is generated
and shows the digest's facts on the pages themselves.

**Where the model runs.** On this machine: the model is served by a local
Ollama (ADR-0022 Amendment A), reached on a loopback address only — any other
address is refused when the service is built. No key, no account, and nothing
leaves the machine. If Ollama is not running, or the model has not been pulled,
the assistant reports itself unavailable and says which.

The conversation is held by the browser and sent with each question; the server
keeps no transcript.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from attribution_platform.api.errors import ApiError, BackendError, InvalidIdentifierError

ASSISTANT_VERSION = "assistant/3"
DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.1:8b"
URL_VARIABLE = "ATTRIBUTION_ASSISTANT_URL"
MODEL_VARIABLE = "ATTRIBUTION_ASSISTANT_MODEL"

MAX_TURNS = 40
MAX_MESSAGE_CHARS = 4_000
MAX_DIGEST_CHARS = 60_000
MAX_REPLY_TOKENS = 1_500
#: The context window asked of the model: sized to the request, within these bounds.
MIN_CONTEXT_TOKENS = 8_192
MAX_CONTEXT_TOKENS = 32_768
#: A deliberately low estimate of characters per token, so the window is never short.
_CHARS_PER_TOKEN = 3
#: A local model on a CPU reads a long digest slowly; the first answer may take minutes.
_ANSWER_TIMEOUT_SECONDS = 900.0
_PROBE_TIMEOUT_SECONDS = 3.0
#: How long Ollama keeps the model loaded after an answer.
_KEEP_ALIVE = "30m"
_THINKING = re.compile(r"<think>.*?</think>", re.DOTALL)

SYSTEM_PROMPT = """You are the analyst assistant of a threat detection and attribution platform. \
You help a SOC analyst understand ONE investigation: what was detected in a set of logs, the \
MITRE ATT&CK techniques, the attack chain, indicators, which threat groups the behaviour matches, \
and what to do about it.

Rules you must follow:
1. Answer ONLY from the INVESTIGATION DIGEST below. It is the complete set of facts you have. \
Do not add techniques, indicators, hosts, times, group names, tools or events that are not in it.
2. If the digest does not contain the answer, say so plainly and, where relevant, name the page \
of the console that holds more detail (Attack chain, ATT&CK matrix, Timeline, Indicators, \
Attribution, Response, or an activity cluster's Evidence tab). Never guess.
3. Attribution: a group is IDENTIFIED only if the digest lists it under "identified_groups" \
(evidence specific to that group's own tooling was observed). Otherwise no group is identified. \
A group under "advisory_indicator_leads" is different: a hash, address or domain seen here equals \
an indicator that a published advisory attributes to that group. Report it as exactly that - an \
advisory indicator match, a lead to verify - and never say that group is identified or \
responsible; indicators are reused and shared. \
"behavioural overlap" is a similarity between the observed \
behaviour and a group's public ATT&CK profile; it is NOT the probability that the group is \
responsible, and the group with the highest overlap is not "the attacker". Say "closest \
behavioural profile" or "consistent with", never "it was X" or "most likely X", unless identified.
4. Indicators are values seen in detected activity. Do not call one malicious unless the digest \
says it matched an advisory; say it is a candidate to verify.
5. Use the ATT&CK ids from the digest (e.g. T1059.001) when you mention techniques.
6. Be concise and concrete. Prefer short paragraphs and short lists. When asked for a summary, \
cover: what was observed, the attack chain in order, attribution, key indicators, recommended \
mitigations.
7. You may explain what an ATT&CK technique or mitigation generally means, but mark any such \
general knowledge as general, separate from what was observed here.
8. Do not provide instructions for carrying out attacks."""


class AssistantDisabledError(ApiError):
    """The assistant is off on this server."""

    status_code = 501


#: ``(url, body, timeout)`` -> response bytes; ``body`` None is a GET.
Transport = Callable[[str, bytes | None, float], bytes]


def _http_transport(url: str, body: bytes | None, timeout: float) -> bytes:
    request = urllib.request.Request(  # noqa: S310 - a loopback http URL, checked at construction
        url,
        data=body,
        headers={"content-type": "application/json"},
        method="GET" if body is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return bytes(response.read())


def loopback_url(url: str) -> str:
    """``url`` without a trailing slash, if it is an http address of this
    machine; anything else is refused, so a question can never leave it."""
    parts = urllib.parse.urlsplit(url.strip())
    host = parts.hostname or ""
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if parts.scheme != "http" or not local or parts.path.strip("/") or parts.query:
        raise ValueError(
            f"{URL_VARIABLE} must be an http address of this machine, e.g. {DEFAULT_URL}"
        )
    return f"http://{parts.netloc}"


def validate_messages(messages: Any) -> list[dict[str, str]]:
    """The conversation as ``[{role, content}]``: alternating, starting and
    ending with the user, within the size bounds. Anything else is refused."""
    if not isinstance(messages, list) or not messages:
        raise InvalidIdentifierError("messages must be a non-empty list")
    if len(messages) > MAX_TURNS:
        raise InvalidIdentifierError(f"a conversation holds at most {MAX_TURNS} messages")
    clean: list[dict[str, str]] = []
    for position, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise InvalidIdentifierError("each message must be an object")
        role, content = message.get("role"), message.get("content")
        if role != ("user" if position % 2 == 0 else "assistant"):
            raise InvalidIdentifierError("messages must alternate, starting with the user")
        if not isinstance(content, str) or not content.strip():
            raise InvalidIdentifierError("each message needs non-empty text")
        if len(content) > MAX_MESSAGE_CHARS:
            raise InvalidIdentifierError(f"a message holds at most {MAX_MESSAGE_CHARS} characters")
        clean.append({"role": str(role), "content": content})
    if clean[-1]["role"] != "user":
        raise InvalidIdentifierError("the last message must be the user's question")
    return clean


def build_digest(
    *,
    investigation: Mapping[str, Any],
    assessment: Mapping[str, Any] | None,
    profile_match: Mapping[str, Any] | None,
    activity: Mapping[str, Any] | None,
    observables: Sequence[Mapping[str, Any]],
    techniques: Mapping[str, Mapping[str, Any]],
    emulation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The facts the assistant may use, from stored records only.
    ``techniques``: ATT&CK id -> ``{name, tactics}`` (the served catalogue)."""
    events = list((activity or {}).get("events") or ())
    by_technique: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("attack_object_type") != "attack-pattern" or not event.get("attack_id"):
            continue
        row = by_technique.setdefault(
            str(event["attack_id"]),
            {"detections": 0, "first_seen": event.get("time"), "hosts": set(), "processes": set()},
        )
        row["detections"] += 1
        if event.get("time") and (row["first_seen"] is None or event["time"] < row["first_seen"]):
            row["first_seen"] = event["time"]
        if event.get("host"):
            row["hosts"].add(event["host"])
        if event.get("label"):
            row["processes"].add(event["label"])
    observed = [
        {
            "id": attack_id,
            "name": techniques.get(attack_id, {}).get("name"),
            "tactics": techniques.get(attack_id, {}).get("tactics", []),
            "detections": row["detections"],
            "first_seen": row["first_seen"],
            "hosts": sorted(row["hosts"])[:6],
            "seen_in": sorted(row["processes"])[:6],
        }
        for attack_id, row in sorted(by_technique.items())
    ]
    stage_first: dict[str, str] = {}
    stage_techniques: dict[str, set[str]] = {}
    for technique in observed:
        for tactic in technique["tactics"]:
            stage_techniques.setdefault(tactic, set()).add(technique["id"])
            first = technique["first_seen"]
            if first and (tactic not in stage_first or first < stage_first[tactic]):
                stage_first[tactic] = first
    chain = [
        {"tactic": tactic, "first_seen": first, "techniques": sorted(stage_techniques[tactic])}
        for tactic, first in sorted(stage_first.items(), key=lambda item: (item[1], item[0]))
    ]
    leads = [
        *((assessment or {}).get("actor_leads") or ()),
        *((assessment or {}).get("indicator_leads") or ()),
    ]

    def named(key: str) -> list[str]:
        return sorted(
            {
                f"{lead['actor_name']} ({lead.get('actor_attack_id') or 'no ATT&CK id'})"
                for lead in (assessment or {}).get(key) or ()
            }
        )

    # Two different things (ADR-0013, ADR-0018): evidence specific to a group's own
    # tooling identifies it; an advisory indicator match is a third party's lead.
    identified, advisory_leads = named("actor_leads"), named("indicator_leads")
    match = profile_match or {}
    digest: dict[str, Any] = {
        "source": investigation.get("source_id"),
        "attack_knowledge_base": investigation.get("attack_kb_version"),
        "detections_total": investigation.get("evidence"),
        "activity_clusters": len(investigation.get("units") or ()),
        "hosts": sorted({e["host"] for e in events if e.get("host")})[:20],
        "time_range": [
            min((e["time"] for e in events if e.get("time")), default=None),
            max((e["time"] for e in events if e.get("time")), default=None),
        ],
        "observed_techniques": observed,
        "attack_chain_by_first_observation": chain,
        "attribution": {
            "statement": (assessment or {}).get("statement"),
            "reasons": list((assessment or {}).get("reasons") or ()),
            "identified_groups": identified,
            "advisory_indicator_leads": advisory_leads,
            "group_specific_evidence": [
                {
                    "group": lead.get("actor_name"),
                    "basis": "tooling artefact" if "claim" in lead else "advisory indicator",
                    "detail": str(lead.get("claim") or lead.get("indicator_name") or "")[:400],
                }
                for lead in leads[:12]
            ],
            "closest_behavioural_profiles": [
                {
                    "group": m["name"],
                    "id": m["candidate_id"],
                    "behavioural_overlap_percent": round(100 * float(m["overlap"])),
                    "matched_techniques": m["matched_technique_ids"],
                    "identified": m.get("named_by") == "actor_specific",
                    "advisory_indicator_lead": m.get("named_by") == "advisory_indicator",
                }
                for m in (match.get("matches") or ())[:15]
            ],
            "matching_groups_total": len(match.get("matches") or ()),
            "indistinguishable_clusters": [
                {
                    "label": c["label"],
                    "behavioural_overlap_percent": round(100 * float(c["overlap"])),
                    "members": list(c["member_names"])[:15],
                    "matched_techniques": c["matched_technique_ids"],
                }
                for c in (match.get("clusters") or ())[:6]
            ],
            "limits": list((assessment or {}).get("limits") or ()),
        },
        "observables": [
            {
                "kind": o["kind"],
                "value": o["value"],
                "scope": o.get("scope"),
                "of": o.get("context"),
                "techniques": o.get("technique_ids"),
                "times_seen": o.get("observations"),
                "matches_advisory": o["advisory"] is not None,
                "advisory": o.get("advisory"),
            }
            for o in list(observables)[:80]
        ],
        "observables_total": len(observables),
        "recommended_mitigations": [
            {
                "id": m["mitigation_id"],
                "name": m["name"],
                "addresses": m["technique_ids"],
                "summary": str(m["description"])[:320],
            }
            for m in (match.get("mitigations") or ())[:14]
        ],
        "techniques_without_recorded_mitigation": list(
            match.get("techniques_without_mitigation") or ()
        ),
    }
    if emulation is not None:
        digest["detection_validation"] = {
            "tool": emulation.get("tool"),
            "outcome_counts": emulation.get("outcome_counts"),
            "steps": [
                {
                    "name": s["name"],
                    "technique": s["technique_id"],
                    "outcome": s["outcome"],
                }
                for s in (emulation.get("steps") or ())[:40]
            ],
        }
    return digest


def render_digest(digest: Mapping[str, Any]) -> str:
    """The digest as the text the model reads, bounded in size: the longest
    lists are shortened first, and the text says so."""
    text = json.dumps(digest, separators=(",", ":"), sort_keys=False, ensure_ascii=False)
    if len(text) <= MAX_DIGEST_CHARS:
        return text
    trimmed = dict(digest)
    trimmed["observables"] = list(digest.get("observables") or ())[:25]
    trimmed["observed_techniques"] = list(digest.get("observed_techniques") or ())[:80]
    trimmed["note"] = "Lists were shortened to fit; totals are still exact."
    return json.dumps(trimmed, separators=(",", ":"), ensure_ascii=False)[:MAX_DIGEST_CHARS]


def context_tokens(system: str, conversation: Sequence[Mapping[str, str]]) -> int:
    """The context window to ask for: what the request needs plus the reply,
    rounded up to 4,096 and kept within the bounds."""
    characters = len(system) + sum(len(m["content"]) for m in conversation)
    needed = math.ceil(characters / _CHARS_PER_TOKEN) + MAX_REPLY_TOKENS
    rounded = 4_096 * math.ceil(needed / 4_096)
    return max(MIN_CONTEXT_TOKENS, min(MAX_CONTEXT_TOKENS, rounded))


@dataclass(frozen=True)
class AssistantService:
    """Asks a model served by Ollama on this machine."""

    base_url: str = DEFAULT_URL
    model: str = DEFAULT_MODEL
    transport: Transport = _http_transport

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", loopback_url(self.base_url))

    def _unavailable(self) -> str | None:
        """Why a question cannot be answered now: ``not_running``,
        ``model_missing``, or None when the model is ready."""
        try:
            listed = json.loads(
                self.transport(f"{self.base_url}/api/tags", None, _PROBE_TIMEOUT_SECONDS)
            )
            names = {str(m.get("name")) for m in listed["models"]}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return "not_running"
        wanted = {self.model, f"{self.model}:latest"}
        return None if names & wanted else "model_missing"

    def describe(self) -> dict[str, Any]:
        reason = self._unavailable()
        return {
            "enabled": reason is None,
            "model": self.model,
            "version": ASSISTANT_VERSION,
            "reason": reason,
        }

    def answer(self, digest: Mapping[str, Any], messages: Any) -> dict[str, Any]:
        conversation = validate_messages(messages)
        system = f"{SYSTEM_PROMPT}\n\nINVESTIGATION DIGEST\n{render_digest(digest)}"
        body = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "system", "content": system}, *conversation],
                "stream": False,
                "keep_alive": _KEEP_ALIVE,
                "options": {
                    "num_ctx": context_tokens(system, conversation),
                    "num_predict": MAX_REPLY_TOKENS,
                    "temperature": 0.2,
                },
            }
        ).encode("utf-8")
        try:
            raw = self.transport(f"{self.base_url}/api/chat", body, _ANSWER_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise BackendError(
                    f"the model {self.model} is not installed in Ollama (ollama pull {self.model})"
                ) from exc
            raise BackendError(f"Ollama answered HTTP {exc.code}") from exc
        except TimeoutError as exc:
            raise BackendError("the local model took too long to answer") from exc
        except OSError as exc:
            raise BackendError("Ollama is not running on this machine") from exc
        try:
            payload = json.loads(raw)
            reply = _THINKING.sub("", str(payload["message"]["content"]))
        except (ValueError, KeyError, TypeError) as exc:
            raise BackendError("the local model's answer could not be read") from exc
        if not reply.strip():
            raise BackendError("the local model returned no text")
        return {"reply": reply.strip(), "model": str(payload.get("model", self.model))}


def disabled() -> dict[str, Any]:
    return {"enabled": False, "model": None, "version": ASSISTANT_VERSION, "reason": "off"}


def service_from_env(env: Mapping[str, str]) -> AssistantService:
    """The service for the Ollama address and model the environment names
    (defaults: this machine's standard port, :data:`DEFAULT_MODEL`). A
    non-loopback address raises ``ValueError``."""
    return AssistantService(
        base_url=(env.get(URL_VARIABLE) or DEFAULT_URL).strip(),
        model=(env.get(MODEL_VARIABLE) or DEFAULT_MODEL).strip(),
    )


__all__ = [
    "ASSISTANT_VERSION",
    "DEFAULT_MODEL",
    "DEFAULT_URL",
    "MODEL_VARIABLE",
    "SYSTEM_PROMPT",
    "URL_VARIABLE",
    "AssistantDisabledError",
    "AssistantService",
    "build_digest",
    "context_tokens",
    "disabled",
    "loopback_url",
    "render_digest",
    "service_from_env",
    "validate_messages",
]
