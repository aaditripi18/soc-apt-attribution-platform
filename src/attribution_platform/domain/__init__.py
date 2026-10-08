"""Core domain contracts — the source-agnostic boundary (gate G0.3).

This package defines the immutable contracts that establish the boundary
between telemetry normalization and the later Evidence/Attribution layers
(docs/architecture/12 §D.2, docs/architecture/06). The chain:

    raw telemetry (referenced, not stored)
        -> Observation      (normalized telemetry — this layer)
        -> Evidence         (derived, analyst-meaningful claim — this layer)
        -> Attribution      (later gates; NOT defined here)

Hard rules for this package:

- Source-agnostic: no Sysmon-/collector-/Elastic-specific fields; nothing
  mandatory that a legitimate source cannot provide.
- Deeply immutable: every contract is a frozen dataclass whose fields are
  only scalars, ``tuple``, or other frozen dataclasses — no mutable mapping
  or list is exposed at any depth.
- Provenance is first-class: every derived object (Evidence) retains a link
  back to the supporting Observation(s).
- MUST NOT import from ``attribution_platform.sources``,
  ``attribution_platform.dataplane``, or ``attribution_platform.attack_knowledge``
  (the ATT&CK *reference* is a pure pointer that never loads the KB).

Gate status:

- **G0.3 (implemented):** the Observation, Evidence, Provenance, and ATT&CK
  reference contracts, their enums/entity value objects, and deterministic
  serialization. **Contracts only** — no extraction/derivation logic, no
  attribution/scoring, no source adapters, no persistence (see
  docs/architecture/13, G0.3 forbidden scope).
- **Not yet implemented:** Observation/Evidence *derivation* pipelines
  (G0.5), source adapters (G0.4), and everything in the attribution engine.
"""

from __future__ import annotations

from attribution_platform.domain.attack import AttackRef
from attribution_platform.domain.entities import (
    AccountChangeRef,
    AuditRef,
    AwsCloudTrailRef,
    AzureActivityRef,
    CloudRef,
    CodeSignature,
    CredentialReadRef,
    DllRef,
    DnsRef,
    EntraRef,
    EventMetadata,
    FileRef,
    FileStreamRef,
    GitHubAuditRef,
    HashSet,
    HostRef,
    KerberosRef,
    KubernetesAuditRef,
    LogonRef,
    NetworkEndpoint,
    NetworkInfo,
    O365Ref,
    ObjectAccessRef,
    ObserverRef,
    OktaRef,
    PeInfo,
    PipeRef,
    PowerShellRef,
    PrivilegeRef,
    ProcessAccessRef,
    ProcessRef,
    RegistryRef,
    RemoteThreadRef,
    ScheduledTaskRef,
    ServiceRef,
    ShareRef,
    TimeSpan,
    UserAgentRef,
    UserRef,
    WfpFilterRef,
    WmiRef,
    ZeekRef,
)
from attribution_platform.domain.enums import EvidenceQuality, EvidenceType, TimePrecision
from attribution_platform.domain.errors import DomainContractError
from attribution_platform.domain.evidence import EVIDENCE_SCHEMA_VERSION, Evidence
from attribution_platform.domain.observation import OBSERVATION_SCHEMA_VERSION, Observation
from attribution_platform.domain.provenance import DerivationProvenance, SourceRef
from attribution_platform.domain.serialization import to_canonical_json, to_serializable

__all__ = [
    "AuditRef",
    "ObserverRef",
    "ZeekRef",
    "OktaRef",
    "GitHubAuditRef",
    "KubernetesAuditRef",
    "AzureActivityRef",
    "AwsCloudTrailRef",
    "CloudRef",
    "EntraRef",
    "O365Ref",
    "UserAgentRef",
    "WfpFilterRef",
    "ServiceRef",
    "ScheduledTaskRef",
    "PrivilegeRef",
    "KerberosRef",
    "CredentialReadRef",
    "AccountChangeRef",
    # errors
    "DomainContractError",
    # enums
    "EvidenceType",
    "EvidenceQuality",
    "TimePrecision",
    # provenance
    "SourceRef",
    "DerivationProvenance",
    # attack reference
    "AttackRef",
    # entity value objects
    "HashSet",
    "FileRef",
    "ProcessRef",
    "PeInfo",
    "CodeSignature",
    "DllRef",
    "RegistryRef",
    "ProcessAccessRef",
    "RemoteThreadRef",
    "DnsRef",
    "FileStreamRef",
    "PipeRef",
    "WmiRef",
    "PowerShellRef",
    "LogonRef",
    "ObjectAccessRef",
    "ShareRef",
    "HostRef",
    "UserRef",
    "NetworkEndpoint",
    "NetworkInfo",
    "EventMetadata",
    "TimeSpan",
    # top-level contracts
    "Observation",
    "Evidence",
    "OBSERVATION_SCHEMA_VERSION",
    "EVIDENCE_SCHEMA_VERSION",
    # serialization
    "to_serializable",
    "to_canonical_json",
]
