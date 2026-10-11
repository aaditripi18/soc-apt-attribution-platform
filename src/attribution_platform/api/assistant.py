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

**What leaves the machine.** Only when a question is asked, and only if an API
key was configured by the operator: the digest, the conversation and the
question go to the model provider's API. Command lines and raw events are not
in the digest. Without a key the assistant is off and nothing is sent.

The conversation is held by the browser and sent with each question; the server
keeps no transcript.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from attribution_platform.api.errors import ApiError, BackendError, InvalidIdentifierError

ASSISTANT_VERSION = "assistant/1"
API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-opus-5-5"
KEY_VARIABLE = "ANTHROPIC_API_KEY"
MODEL_VARIABLE = "ATTRIBUTION_ASSISTANT_MODEL"

MAX_TURNS = 40
MAX_MESSAGE_CHARS = 4_000
MAX_DIGEST_CHARS = 60_000
MAX_REPLY_TOKENS = 1_500
_TIMEOUT_SECONDS = 120

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
3. Attribution: a group is IDENTIFIED only if the digest lists it under "identified_groups". \
Otherwise no group is identified. "behavioural overlap" is a similarity between the observed \
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
    """No API key was configured: the assistant is off."""

    status_code = 501


Transport = Callable[[str, Mapping[str, str], bytes], bytes]


def _http_transport(url: str, headers: Mapping[str, str], body: bytes) -> bytes:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
        return bytes(response.read())


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
    identified = sorted(
        {
            f"{lead['actor_name']} ({lead.get('actor_attack_id') or 'no ATT&CK id'})"
            for lead in leads
        }
    )
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
                    "identified": m.get("named_by") is not None,
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
    text = json.dumps(digest, indent=1, sort_keys=False, ensure_ascii=False)
    if len(text) <= MAX_DIGEST_CHARS:
        return text
    trimmed = dict(digest)
    trimmed["observables"] = list(digest.get("observables") or ())[:25]
    trimmed["observed_techniques"] = list(digest.get("observed_techniques") or ())[:80]
    trimmed["note"] = "Lists were shortened to fit; totals are still exact."
    return json.dumps(trimmed, indent=1, sort_keys=False, ensure_ascii=False)[:MAX_DIGEST_CHARS]


@dataclass(frozen=True)
class AssistantService:
    """Calls the model provider. ``api_key`` is read from the environment by the
    serving command and never leaves this object except as the request header."""

    api_key: str
    model: str = DEFAULT_MODEL
    transport: Transport = _http_transport

    def describe(self) -> dict[str, Any]:
        return {"enabled": True, "model": self.model, "version": ASSISTANT_VERSION}

    def answer(self, digest: Mapping[str, Any], messages: Any) -> dict[str, Any]:
        conversation = validate_messages(messages)
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": MAX_REPLY_TOKENS,
                "system": f"{SYSTEM_PROMPT}\n\nINVESTIGATION DIGEST\n{render_digest(digest)}",
                "messages": conversation,
            }
        ).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
        }
        try:
            raw = self.transport(API_URL, headers, body)
        except urllib.error.HTTPError as exc:
            # the provider's status only: its body may echo request details
            raise BackendError(f"the model provider answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackendError(f"the model provider could not be reached: {exc}") from exc
        try:
            payload = json.loads(raw)
            reply = "".join(
                block["text"] for block in payload["content"] if block.get("type") == "text"
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise BackendError("the model provider's answer could not be read") from exc
        if not reply.strip():
            raise BackendError("the model provider returned no text")
        return {"reply": reply, "model": str(payload.get("model", self.model))}


def disabled() -> dict[str, Any]:
    return {"enabled": False, "model": None, "version": ASSISTANT_VERSION}


def service_from_env(env: Mapping[str, str]) -> AssistantService | None:
    key = (env.get(KEY_VARIABLE) or "").strip()
    if not key:
        return None
    return AssistantService(api_key=key, model=(env.get(MODEL_VARIABLE) or DEFAULT_MODEL).strip())


__all__ = [
    "ASSISTANT_VERSION",
    "DEFAULT_MODEL",
    "KEY_VARIABLE",
    "MODEL_VARIABLE",
    "SYSTEM_PROMPT",
    "AssistantDisabledError",
    "AssistantService",
    "build_digest",
    "disabled",
    "render_digest",
    "service_from_env",
    "validate_messages",
]
