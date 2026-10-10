"""Source-agnostic entity value objects used inside Observations/Evidence.

Gate G0.3. These are the *curated normalized field groups* (host, user,
process, network, file, event metadata, time span) that a legitimate
telemetry source may populate — ECS-aligned generic concepts, never
Sysmon- or collector-specific. Every field is optional: a source populates
what it has and leaves the rest absent (``None`` / empty tuple). Nothing
here is mandatory, and there is no generic ``dict[str, Any]`` bag — raw,
source-native fields that have no normalized home are preserved by
*reference* to the raw record via :class:`~attribution_platform.domain.provenance.SourceRef`,
not copied into these structures (docs/architecture/13, G0.3 §6).

All classes are ``@dataclass(frozen=True)`` with only scalar or ``tuple``
fields, so they are deeply immutable and value-equal by construction — no
mutable container is ever exposed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from attribution_platform.domain.errors import DomainContractError, ensure_aware_datetime


@dataclass(frozen=True)
class HashSet:
    """Cryptographic hashes of a file/artifact (all optional)."""

    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class FileRef:
    """A file/path artifact referenced by an observation (all optional)."""

    path: str | None = None
    name: str | None = None
    directory: str | None = None
    hashes: HashSet | None = None


@dataclass(frozen=True)
class PeInfo:
    """Portable-Executable version-info metadata of a process image (all
    optional) — ECS ``process.pe.*``. Values are the image's own embedded
    resource strings as the source reported them, never inferred."""

    original_file_name: str | None = None
    description: str | None = None
    product: str | None = None
    company: str | None = None


@dataclass(frozen=True)
class CodeSignature:
    """Code-signing facts about a binary as the source reported them (all
    optional) — ECS ``*.code_signature.*``. ``signed`` is whether a signature
    was present; ``status`` is the source's verification result (e.g.
    ``Valid``); ``subject_name`` is the signer."""

    signed: bool | None = None
    subject_name: str | None = None
    status: str | None = None


@dataclass(frozen=True)
class DllRef:
    """A library loaded into a process (all optional) — ECS ``dll.*``.

    ``pe``/``code_signature`` describe the **loaded library**, not the
    loading process (which is the Observation's ``process``)."""

    path: str | None = None
    name: str | None = None
    pe: PeInfo | None = None
    code_signature: CodeSignature | None = None


@dataclass(frozen=True)
class RegistryRef:
    """A Windows registry key or value touched by an event (all optional) —
    ECS ``registry.*``. ``path`` is the full path as the source reported it
    (a key path, or key path plus value name); ``data`` is the value data as
    the source rendered it as a string (e.g. Sysmon's ``Details``). The kind of
    operation lives on the Observation's ``event`` (``type``/``action``)."""

    path: str | None = None
    data: str | None = None


@dataclass(frozen=True)
class ProcessAccessRef:
    """One process opening a handle to another (all optional). The acting
    process is the Observation's ``process``; the accessed one is its
    ``target_process``. ``granted_access`` is the access mask as the source
    rendered it (e.g. ``0x1010``); ``call_trace`` is the source's stack
    string."""

    granted_access: str | None = None
    call_trace: str | None = None


@dataclass(frozen=True)
class RemoteThreadRef:
    """A thread created by one process inside another (all optional). The
    creating process is the Observation's ``process``; the one receiving the
    thread is its ``target_process``."""

    start_address: str | None = None
    start_module: str | None = None
    start_function: str | None = None


@dataclass(frozen=True)
class DnsRef:
    """A DNS lookup made by a process (all optional). ``question_name`` is the
    queried name (ECS ``dns.question.name``); ``query_status`` is the source's
    status code as a string (Sysmon ``QueryStatus``, a Win32 status, ``0`` =
    success); ``results`` is the source's raw answer string."""

    question_name: str | None = None
    query_status: str | None = None
    results: str | None = None


@dataclass(frozen=True)
class FileStreamRef:
    """An alternate data stream written to a file (all optional); the file is
    the Observation's ``file``. ``contents`` is the stream content as the source
    reported it (e.g. a ``Zone.Identifier`` body; Sysmon writes ``-`` when it
    does not capture it); ``hashes`` is the source's combined hash string
    (e.g. ``SHA1=…,MD5=…``) exactly as rendered."""

    contents: str | None = None
    hashes: str | None = None


@dataclass(frozen=True)
class PipeRef:
    """A named pipe created or connected to (all optional). Whether it was
    created or connected is on the Observation's ``event``."""

    name: str | None = None


@dataclass(frozen=True)
class WmiRef:
    """A WMI event-subscription object (filter, consumer or filter-to-consumer
    binding) as the source reported it (all optional); which of the three it is
    lives on the Observation's ``event.action``. Values are kept exactly as
    reported (Sysmon quotes names and escapes paths)."""

    operation: str | None = None
    name: str | None = None
    namespace: str | None = None
    query: str | None = None
    consumer_type: str | None = None
    destination: str | None = None
    filter: str | None = None
    consumer: str | None = None


@dataclass(frozen=True)
class PowerShellRef:
    """PowerShell engine logging (all optional) — ECS ``powershell.*``.

    Script-block logging: ``script_block_text`` (one logged part of a script
    block), ``script_block_id``, ``script_path``, and ``message_number`` /
    ``message_total`` (a long script block is logged in several parts, each
    its own event). Module/pipeline logging: ``payload`` (the logged
    invocation details) and ``context_info`` (the host context block). All
    text is kept exactly as the source logged it."""

    script_block_text: str | None = None
    script_block_id: str | None = None
    script_path: str | None = None
    message_number: int | None = None
    message_total: int | None = None
    payload: str | None = None
    context_info: str | None = None


@dataclass(frozen=True)
class LogonRef:
    """Windows logon and credential-validation facts (all optional; ADR-0008
    Security log). Values are kept exactly as the source logged them —
    including Windows' ``-`` "no value" marker and unrendered ``%%NNNN``
    message references, which detection content is written against.

    ``workstation_name`` is the logon events' ``WorkstationName``;
    ``workstation`` is credential validation's ``Workstation`` (distinct source
    fields, kept distinct). ``authentication_package`` is the logon events'
    ``AuthenticationPackageName``; ``package_name`` is credential validation's
    ``PackageName``. ``logon_id`` is the new session's id (``TargetLogonId``)."""

    logon_type: str | None = None
    logon_process: str | None = None
    authentication_package: str | None = None
    package_name: str | None = None
    lm_package: str | None = None
    key_length: str | None = None
    impersonation_level: str | None = None
    elevated_token: str | None = None
    logon_id: str | None = None
    workstation_name: str | None = None
    workstation: str | None = None
    status: str | None = None
    sub_status: str | None = None
    target_outbound_user_name: str | None = None
    # Security batch B: 4625 failure reason, 4648 explicit-credential target,
    # and the acting (subject) session's logon id.
    failure_reason: str | None = None
    target_server_name: str | None = None
    target_info: str | None = None
    subject_logon_id: str | None = None


@dataclass(frozen=True)
class ObjectAccessRef:
    """A Windows audited object handle request/access (all optional; ADR-0008
    Security log): object manager server, type and name, the handle, the
    access mask and the access list (unrendered ``%%NNNN`` references, as
    logged), and for registry values the value name and new value.

    Security batch B adds the registry-change facts of 4657 (old value, value
    types and operation type, as logged — often ``%%NNNN`` references) and the
    directory-service / SAM facts of 4661 / 4662 (``properties``: the accessed
    property-set and extended-right GUIDs; ``additional_info``)."""

    server: str | None = None
    type: str | None = None
    name: str | None = None
    handle_id: str | None = None
    access_mask: str | None = None
    access_list: str | None = None
    value_name: str | None = None
    new_value: str | None = None
    old_value: str | None = None
    new_value_type: str | None = None
    old_value_type: str | None = None
    operation_type: str | None = None
    properties: str | None = None
    additional_info: str | None = None


@dataclass(frozen=True)
class ShareRef:
    """A network share access (all optional; ADR-0008 Security log): share name,
    its local path, and for detailed share auditing the relative target
    name (the file or directory accessed inside the share)."""

    name: str | None = None
    local_path: str | None = None
    relative_target_name: str | None = None


@dataclass(frozen=True)
class ServiceRef:
    """A Windows service an event is about (all optional; ADR-0008 Security
    batch B): the installed service of 4697 (name, image path, type, start
    type, account — exactly as logged, e.g. ``0x10`` / ``2``) or the Kerberos
    service ticket target of 4768 / 4769 / 4771 (``name`` and ``id`` =
    ``ServiceName`` / ``ServiceSid``). Both events log ``ServiceName`` under
    the same name and meaning — the service the event concerns."""

    name: str | None = None
    id: str | None = None
    file_name: str | None = None
    type: str | None = None
    start_type: str | None = None
    account: str | None = None


@dataclass(frozen=True)
class KerberosRef:
    """Kerberos ticket facts of 4768 / 4769 / 4771 (all optional), as logged:
    ticket options and encryption type (hex strings, e.g. ``0x17`` = RC4),
    pre-authentication type and the certificate thumbprint of PKINIT
    requests. The result code is ``LogonRef.status`` (Sigma's shared
    ``Status``)."""

    ticket_options: str | None = None
    ticket_encryption_type: str | None = None
    pre_auth_type: str | None = None
    cert_thumbprint: str | None = None


@dataclass(frozen=True)
class ScheduledTaskRef:
    """A scheduled-task registration change (4698 created, 4702 updated; all
    optional): the task path and its XML definition exactly as logged
    (``content`` = 4698 ``TaskContent``, ``content_new`` = 4702
    ``TaskContentNew``)."""

    name: str | None = None
    content: str | None = None
    content_new: str | None = None


@dataclass(frozen=True)
class PrivilegeRef:
    """Privileges assigned or exercised (4672 / 4673 / 4674; all optional):
    the ``PrivilegeList`` exactly as logged (whitespace-separated names) and,
    for 4673, the privileged ``Service`` called."""

    privilege_list: str | None = None
    service: str | None = None


@dataclass(frozen=True)
class AccountChangeRef:
    """User / group account management facts (4720, 4722, 4724, 4728, 4732,
    4738; all optional), as logged — the account or group acted upon is
    ``Observation.target_user``. ``old_uac_value`` / ``new_uac_value`` are the
    hex ``userAccountControl`` values; ``member_*`` the account added to a
    group."""

    sam_account_name: str | None = None
    user_principal_name: str | None = None
    display_name: str | None = None
    old_uac_value: str | None = None
    new_uac_value: str | None = None
    user_account_control: str | None = None
    sid_history: str | None = None
    primary_group_id: str | None = None
    member_name: str | None = None
    member_sid: str | None = None


@dataclass(frozen=True)
class CredentialReadRef:
    """A Credential Manager read (5379; all optional), as logged: the
    credential's target name, its type, the read operation, the count
    returned and the return code."""

    target_name: str | None = None
    type: str | None = None
    read_operation: str | None = None
    count_returned: str | None = None
    return_code: str | None = None


@dataclass(frozen=True)
class AuditRef:
    """One Linux Audit record (ADR-0010 D4; all optional except as noted).

    Values are kept as auditd logs them, with only auditd's own encoding
    undone: an *untrusted string* field (EXECVE arguments, ``name``, ``comm``,
    ``exe``) logged unquoted is hex-encoded and is decoded exactly; ``(null)``
    means absent. ``a0``–``a7`` therefore mean what the record type defines —
    decoded argv strings in an ``EXECVE`` record, raw hex syscall arguments in
    a ``SYSCALL`` record — exactly as Sigma's auditd rules read them.
    ``syscall_name`` and the ``*_name`` account fields come only from the
    ENRICHED log format's interpreted suffix (never from a syscall table).
    ``event_serial`` is the kernel's event serial, shared by every record of
    one audit event."""

    record_type: str | None = None
    event_serial: str | None = None
    syscall: str | None = None
    syscall_name: str | None = None
    success: str | None = None
    exit: str | None = None
    argc: str | None = None
    a0: str | None = None
    a1: str | None = None
    a2: str | None = None
    a3: str | None = None
    a4: str | None = None
    a5: str | None = None
    a6: str | None = None
    a7: str | None = None
    item: str | None = None
    name: str | None = None
    nametype: str | None = None
    comm: str | None = None
    unit: str | None = None
    op: str | None = None
    res: str | None = None
    key: str | None = None
    auid: str | None = None
    uid: str | None = None
    euid: str | None = None
    ses: str | None = None
    tty: str | None = None


@dataclass(frozen=True)
class WfpFilterRef:
    """A Windows Filtering Platform filter change (5441 present at startup,
    5447 changed; all optional), as logged — the filter, its provider and
    provider context, the layer, the callout and the change type."""

    name: str | None = None
    key: str | None = None
    type: str | None = None
    change_type: str | None = None
    provider_name: str | None = None
    provider_context_name: str | None = None
    layer_name: str | None = None
    callout_name: str | None = None


@dataclass(frozen=True)
class CloudRef:
    """ECS ``cloud.*`` for a cloud service event (ADR-0011 D3; all optional).

    ``provider`` is set only where the source states it (Elastic's own value for
    that source); ``account_id`` is the tenant / organization / account the
    event belongs to, as logged."""

    provider: str | None = None
    account_id: str | None = None
    region: str | None = None
    service_name: str | None = None


@dataclass(frozen=True)
class UserAgentRef:
    """ECS ``user_agent.original``: the client's user-agent string, as logged."""

    original: str | None = None


@dataclass(frozen=True)
class EntraRef:
    """One Microsoft Entra ID record from an Azure Monitor diagnostic export
    (ADR-0011 D3; all optional). Values are kept exactly as logged; JSON
    booleans are recorded as ``"true"`` / ``"false"``.

    ``log_category`` is the export's top-level ``category`` (``SignInLogs``,
    ``AuditLogs``, ``UserRiskEvents``, …); ``audit_category`` is an audit
    record's own ``properties.category`` (``RoleManagement``, …) — the Log
    Analytics ``AuditLogs.Category`` column. ``operation_name`` is the top-level
    ``operationName``; ``result_type`` / ``result_description`` the top-level
    ``resultType`` / ``resultDescription``; every other field is the record's
    ``properties`` value of the same name."""

    log_category: str | None = None
    operation_name: str | None = None
    record_id: str | None = None
    correlation_id: str | None = None
    result_type: str | None = None
    result_description: str | None = None
    result: str | None = None
    audit_category: str | None = None
    activity_display_name: str | None = None
    logged_by_service: str | None = None
    operation_type: str | None = None
    authentication_requirement: str | None = None
    conditional_access_status: str | None = None
    client_app_used: str | None = None
    app_id: str | None = None
    app_display_name: str | None = None
    resource_display_name: str | None = None
    home_tenant_id: str | None = None
    resource_tenant_id: str | None = None
    device_is_compliant: str | None = None
    risk_state: str | None = None
    risk_level: str | None = None
    risk_detail: str | None = None
    risk_event_type: str | None = None


@dataclass(frozen=True)
class O365Ref:
    """One Office 365 Management Activity API (unified audit log) record
    (ADR-0011 D3; all optional), with the common-schema fields and the
    record-type fields Sigma's ``m365/audit`` rules read, as logged."""

    record_id: str | None = None
    record_type: str | None = None
    workload: str | None = None
    operation: str | None = None
    result_status: str | None = None
    user_type: str | None = None
    object_id: str | None = None
    application_id: str | None = None
    directionality: str | None = None
    delivery_action: str | None = None


@dataclass(frozen=True)
class AwsCloudTrailRef:
    """One AWS CloudTrail record (ADR-0011 D3, batch B; all optional), as logged.

    The top-level fields keep CloudTrail's own meaning (``source_ip_address`` is
    ``sourceIPAddress``: an IP address *or* an AWS service name such as
    ``eks.amazonaws.com`` / ``AWS Internal``). The remaining fields are the
    nested values Sigma's ``aws/cloudtrail`` rules read, each named after its
    CloudTrail path (``additionalEventData.MFAUsed`` → ``mfa_used``, …). JSON
    booleans are recorded as ``"true"`` / ``"false"``."""

    event_id: str | None = None
    event_source: str | None = None
    event_name: str | None = None
    event_type: str | None = None
    event_category: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    source_ip_address: str | None = None
    read_only: str | None = None
    request_id: str | None = None
    shared_event_id: str | None = None
    user_identity_type: str | None = None
    user_identity_arn: str | None = None
    user_identity_principal_id: str | None = None
    user_identity_account_id: str | None = None
    user_identity_access_key_id: str | None = None
    user_identity_invoked_by: str | None = None
    mfa_used: str | None = None
    console_login: str | None = None
    request_attribute: str | None = None
    request_enable: str | None = None
    response_publicly_accessible: str | None = None
    response_pending_master_user_password: str | None = None
    #: ``requestParameters`` as logged: the JSON object re-serialised compactly
    #: with its key order kept (ADR-0015 -- Elastic rules read the whole object,
    #: as a string and by sub-field).
    request_parameters: str | None = None


@dataclass(frozen=True)
class OktaRef:
    """One Okta System Log event (ADR-0011 batch C; all optional), as logged.
    ``debug_behaviors`` / ``debug_log_only_security_data`` are the strings Okta
    writes in ``debugContext.debugData``; JSON booleans become ``"true"`` /
    ``"false"``."""

    uuid: str | None = None
    event_type: str | None = None
    legacy_event_type: str | None = None
    display_message: str | None = None
    severity: str | None = None
    outcome_result: str | None = None
    outcome_reason: str | None = None
    actor_id: str | None = None
    actor_type: str | None = None
    actor_alternate_id: str | None = None
    actor_display_name: str | None = None
    transaction_id: str | None = None
    external_session_id: str | None = None
    security_is_proxy: str | None = None
    debug_behaviors: str | None = None
    debug_log_only_security_data: str | None = None


@dataclass(frozen=True)
class GitHubAuditRef:
    """One GitHub audit-log event (enterprise / organization audit-log export or
    stream; ADR-0011 batch C; all optional), as logged."""

    document_id: str | None = None
    action: str | None = None
    operation_type: str | None = None
    actor: str | None = None
    actor_id: str | None = None
    actor_is_bot: str | None = None
    user: str | None = None
    org: str | None = None
    org_id: str | None = None
    business: str | None = None
    business_id: str | None = None
    repo: str | None = None
    visibility: str | None = None


@dataclass(frozen=True)
class KubernetesAuditRef:
    """One Kubernetes API-server audit event (``audit.k8s.io/v1`` ``Event``;
    ADR-0011 batch C; all optional), as logged. ``audit_id`` is shared by the
    events of one request's stages; ``object_*`` are ``objectRef``'s fields."""

    audit_id: str | None = None
    stage: str | None = None
    level: str | None = None
    verb: str | None = None
    request_uri: str | None = None
    response_code: str | None = None
    response_status: str | None = None
    response_reason: str | None = None
    object_resource: str | None = None
    object_subresource: str | None = None
    object_namespace: str | None = None
    object_name: str | None = None
    object_api_group: str | None = None
    object_api_version: str | None = None
    authorization_decision: str | None = None


@dataclass(frozen=True)
class AzureActivityRef:
    """One Azure Activity Log event in the Azure Monitor REST API form (ADR-0011
    batch C; all optional), as logged. ``operation_name``, ``category``,
    ``resource_provider``, ``status`` and ``sub_status`` are the ``.value`` of
    the API's localizable objects (the Log Analytics ``AzureActivity`` columns
    ``OperationNameValue``, ``CategoryValue``, ``ResourceProviderValue``, …)."""

    event_data_id: str | None = None
    operation_id: str | None = None
    correlation_id: str | None = None
    operation_name: str | None = None
    category: str | None = None
    resource_provider: str | None = None
    resource_id: str | None = None
    resource_group: str | None = None
    status: str | None = None
    sub_status: str | None = None
    level: str | None = None
    caller: str | None = None
    authorization_action: str | None = None
    subscription_id: str | None = None
    properties_message: str | None = None


@dataclass(frozen=True)
class ObserverRef:
    """ECS ``observer.*``: the network sensor that recorded the event (ADR-0012
    D5; all optional). A sensor sees traffic; it is not the host the traffic
    came from, so its records carry no ``host``."""

    product: str | None = None
    hostname: str | None = None


@dataclass(frozen=True)
class ZeekRef:
    """One Zeek log record (ADR-0012; all optional), in Zeek's own field names
    and values as logged (``log`` is the Zeek log: ``conn``, ``dns``, …). ``uid``
    identifies one connection across every log; ``fuid`` one file. Booleans are
    ``"true"`` / ``"false"``; a Zeek *set* or *vector* is kept only where its
    elements are listed (``answers``, ``conn_uids``) joined by ``","``, as Zeek's
    own TSV writer joins them."""

    log: str | None = None
    uid: str | None = None
    fuid: str | None = None
    # conn
    service: str | None = None
    conn_state: str | None = None
    history: str | None = None
    duration: str | None = None
    orig_bytes: str | None = None
    resp_bytes: str | None = None
    # dns
    query: str | None = None
    qtype_name: str | None = None
    rcode_name: str | None = None
    z: str | None = None
    answers: str | None = None
    # http
    method: str | None = None
    http_host: str | None = None
    uri: str | None = None
    status_code: str | None = None
    # ssl
    server_name: str | None = None
    ssl_version: str | None = None
    ssl_subject: str | None = None
    ssl_issuer: str | None = None
    ja3: str | None = None
    ja3s: str | None = None
    # kerberos
    request_type: str | None = None
    krb_client: str | None = None
    krb_service: str | None = None
    cipher: str | None = None
    success: str | None = None
    # smb_files / smb_mapping
    smb_action: str | None = None
    smb_path: str | None = None
    smb_name: str | None = None
    share_type: str | None = None
    # dce_rpc
    named_pipe: str | None = None
    endpoint: str | None = None
    operation: str | None = None
    # files
    filename: str | None = None
    mime_type: str | None = None
    file_source: str | None = None
    md5: str | None = None
    sha1: str | None = None
    conn_uids: str | None = None
    # notice
    note: str | None = None
    msg: str | None = None


@dataclass(frozen=True)
class ProcessRef:
    """A process and its immediate parent lineage (all optional).

    ``entity_id``/``parent_entity_id`` are stable per-process identifiers
    where a source provides them (e.g. an ECS ``process.entity_id``); they
    are the source's identifiers, not values this layer invents.

    ``name``/``parent_name`` are **bare file names** (ECS ``process.name`` /
    ``process.parent.name``); full paths belong in ``executable`` /
    ``parent_executable``. Fields added by ADR-0007 D10 step 1 (parent
    executable and command line, working directory, integrity level, PE
    metadata) let detection content match the process-creation fields
    endpoint sources actually report.
    """

    pid: int | None = None
    name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    entity_id: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    parent_entity_id: str | None = None
    parent_executable: str | None = None
    parent_command_line: str | None = None
    working_directory: str | None = None
    integrity_level: str | None = None
    pe: PeInfo | None = None
    #: The image's hashes, as the source computed them (Sysmon process creation);
    #: lower-case hex. Added for indicator matching (ADR-0013).
    hashes: HashSet | None = None


@dataclass(frozen=True)
class HostRef:
    """A host/asset identity (all optional). ``ip`` is a tuple (a host may
    have several addresses); order is preserved as supplied. ``os_type`` is
    ECS ``host.os.type`` (``windows`` / ``linux`` / ``macos``), set by an
    adapter only from a fact it reads (the channel or provider proves the
    platform); detection content is scoped by it (ADR-0010 D2)."""

    id: str | None = None
    name: str | None = None
    ip: tuple[str, ...] = ()
    os_type: str | None = None


@dataclass(frozen=True)
class UserRef:
    """A user/account identity (all optional)."""

    id: str | None = None
    name: str | None = None
    domain: str | None = None


@dataclass(frozen=True)
class NetworkEndpoint:
    """One end of a network connection (all optional)."""

    ip: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class NetworkInfo:
    """Network source/destination information for an observation (all optional)."""

    source: NetworkEndpoint | None = None
    destination: NetworkEndpoint | None = None
    protocol: str | None = None
    transport: str | None = None
    direction: str | None = None


@dataclass(frozen=True)
class EventMetadata:
    """ECS-style event classification (all optional).

    ``category`` and ``type`` are tuples because ECS models them as arrays
    (a single event may carry several categories/types). Order is preserved
    as supplied by the source. ``provider`` / ``code`` are ECS
    ``event.provider`` (the logging provider, e.g.
    ``Microsoft-Windows-Security-Auditing``) and ``event.code`` (the source's
    own event identifier, e.g. ``"4624"``), and ``dataset`` is ECS
    ``event.dataset`` (the log the event belongs to, e.g. ``system.security``
    for the Windows Security channel — Elastic's own dataset name), added for
    the Windows event logs (ADR-0008), whose detection content selects on
    them.
    """

    kind: str | None = None
    category: tuple[str, ...] = ()
    type: tuple[str, ...] = ()
    action: str | None = None
    outcome: str | None = None
    provider: str | None = None
    code: str | None = None
    dataset: str | None = None


@dataclass(frozen=True)
class TimeSpan:
    """A closed time interval [start, end], both timezone-aware.

    Used for derived Evidence that may span multiple observations. Validates
    that both bounds are tz-aware and that ``start <= end`` (fail closed).
    """

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        start = ensure_aware_datetime(self.start, "TimeSpan.start")
        end = ensure_aware_datetime(self.end, "TimeSpan.end")
        if start > end:
            raise DomainContractError(
                f"TimeSpan.start ({start.isoformat()}) must not be after end ({end.isoformat()})"
            )
