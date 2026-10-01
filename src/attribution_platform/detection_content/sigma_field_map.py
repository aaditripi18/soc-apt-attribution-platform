"""Sigma logsource/field → our ECS-aligned Observation fields (ADR-0007 D5),
versioned as :data:`FIELD_MAP_VERSION`. Pure data; no pySigma import.

A mapping is listed **only** when it is exact for every source adapter that
produces that Observation kind today (``sources/sysmon.py``, ``sources/synthetic.py``).
The Sysmon adapter fills these fields from Sysmon's own ``winlog.event_data``
values — the very names Sigma's Windows fields use — so the mapping is 1:1.

Version history: ``/1`` Image, CommandLine (+ network fields). ``/2`` (ADR-0007
D10 step 1) adds ParentImage, ParentCommandLine, CurrentDirectory,
IntegrityLevel, OriginalFileName, Description, Product, Company. ``/3``
(ADR-0008 Wave 1) adds the ``image_load``, ``file_event`` and ``registry_*``
logsources (Sysmon events 7, 11, 12, 13). Field names are per logsource: in
``image_load`` ``OriginalFileName`` etc. describe the loaded DLL, not the process.
``/4`` adds ``process_access``, ``create_remote_thread`` (Sysmon 10, 8: ``Source*``
is the acting ``process``, ``Target*`` the ``target_process``) and ``dns_query``
(Sysmon 22); scopes may now also require an exact ``event.action``. ``/5``
adds ``create_stream_hash`` (15), ``pipe_created`` (17/18), ``wmi_event``
(19/20/21) and ``file_delete`` (23), and ``file_event`` now also requires the
``file_create`` action (stream-hash events are file creations too). ``/6``
adds ``ps_script`` (PowerShell 4104) and ``ps_module`` (PowerShell 4103).
``/7``-``/8`` add the Windows Security channel (batch A). ``/9`` adds Security
batch B (ADR-0008): failed and explicit-credential logons, Kerberos, service
installation, scheduled tasks, privileges, registry / directory-service object
operations, account management, Credential Manager reads and WFP filters.
``/10`` (ADR-0010) scopes every product by operating system (``PRODUCT_OS_SCOPES``)
and adds Linux ``process_creation`` / ``file_event`` / ``network_connection``
(Sysmon for Linux).

Anything else is a *telemetry gap*, reported per rule by the importer — never
approximated. ``UNMAPPED_FIELD_REASONS`` records why the most frequent
unmapped Sigma fields are not mapped, so the gap is explained rather than
silent.

Logsources map to ``has_element`` conditions on ECS ``event.category`` /
``event.type`` (never Sysmon event IDs), keeping imported rules
source-agnostic (doc 12 §D.1).
"""

from __future__ import annotations

from types import MappingProxyType

FIELD_MAP_VERSION = "sigma-field-map/10"

#: ``(product, category)`` → the ``(field_path, operator, value)`` scope
#: conditions an Observation must satisfy to be the kind of event the Sigma
#: rule describes. The first is ``event.category has_element`` (the detection
#: engine indexes on it); ``event.action equals`` is used where a
#: category+type pair alone would be ambiguous. A Windows event-log channel
#: (Sigma ``service``) is scoped by ``event.dataset equals`` instead — also
#: indexed — because one channel holds many kinds of event, which its rules
#: select by ``EventID`` (``event.code``).
LOGSOURCE_SCOPES: MappingProxyType[tuple[str, str], tuple[tuple[str, str, str], ...]] = (
    MappingProxyType(
        {
            ("windows", "process_creation"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "start"),
            ),
            ("windows", "process_termination"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "end"),
            ),
            ("windows", "network_connection"): (
                ("event.category", "has_element", "network"),
                ("event.type", "has_element", "connection"),
            ),
            ("windows", "image_load"): (
                ("event.category", "has_element", "library"),
                ("event.type", "has_element", "start"),
            ),
            ("windows", "file_event"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "creation"),
                ("event.action", "equals", "file_create"),
            ),
            ("windows", "create_stream_hash"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "creation"),
                ("event.action", "equals", "file_stream_create"),
            ),
            ("windows", "file_delete"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "deletion"),
                ("event.action", "equals", "file_delete"),
            ),
            # Sigma pipe_created covers both Sysmon 17 (created) and 18 (connected).
            ("windows", "pipe_created"): (
                ("event.category", "has_element", "file"),
                ("event.action", "startswith", "pipe_"),
            ),
            ("windows", "ps_script"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "info"),
                ("event.action", "equals", "powershell_script_block"),
            ),
            ("windows", "ps_module"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "info"),
                ("event.action", "equals", "powershell_module"),
            ),
            # Sigma wmi_event covers Sysmon 19/20/21.
            ("windows", "wmi_event"): (
                ("event.category", "has_element", "configuration"),
                ("event.action", "startswith", "wmi_"),
            ),
            # Sigma's registry_* categories over Sysmon 12/13 (14, rename, is not
            # supported yet): add = CreateKey, delete = DeleteKey/DeleteValue,
            # set = SetValue, event = any registry event.
            ("windows", "registry_add"): (
                ("event.category", "has_element", "registry"),
                ("event.type", "has_element", "creation"),
            ),
            ("windows", "registry_delete"): (
                ("event.category", "has_element", "registry"),
                ("event.type", "has_element", "deletion"),
            ),
            ("windows", "registry_set"): (
                ("event.category", "has_element", "registry"),
                ("event.type", "has_element", "change"),
            ),
            ("windows", "registry_event"): (("event.category", "has_element", "registry"),),
            ("windows", "process_access"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "access"),
            ),
            ("windows", "create_remote_thread"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "change"),
                ("event.action", "equals", "create_remote_thread"),
            ),
            ("windows", "dns_query"): (
                ("event.category", "has_element", "network"),
                ("event.type", "has_element", "protocol"),
                ("event.action", "equals", "dns_query"),
            ),
            # Sigma service: security = the Windows Security channel.
            ("windows", "security"): (("event.dataset", "equals", "system.security"),),
            # Linux (ADR-0010): the same ECS kinds; the platform is told apart by
            # PRODUCT_OS_SCOPES, never by these conditions.
            ("linux", "process_creation"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "start"),
            ),
            ("linux", "file_event"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "creation"),
                ("event.action", "equals", "file_create"),
            ),
            ("linux", "network_connection"): (
                ("event.category", "has_element", "network"),
                ("event.type", "has_element", "connection"),
            ),
        }
    )
)

#: Sigma product → ``(field_path, operator, value, negate)`` conditions every
#: rule of that product also carries (ADR-0010 D2), placed after the logsource
#: scope so the engine's first-condition index is unchanged. Linux rules require
#: a Linux host; Windows rules require the host **not** to be Linux or macOS, so
#: Windows Observations that predate ``host.os_type`` (fixtures) still match. A
#: Windows rule can therefore never fire on a Linux process, nor the reverse.
PRODUCT_OS_SCOPES: MappingProxyType[str, tuple[tuple[str, str, str, bool], ...]] = (
    MappingProxyType(
        {
            "windows": (
                ("host.os_type", "equals", "linux", True),
                ("host.os_type", "equals", "macos", True),
            ),
            "linux": (("host.os_type", "equals", "linux", False),),
        }
    )
)

#: Registry fields shared by every ``registry_*`` logsource. ``EventType`` is
#: Sysmon's own value (CreateKey/DeleteKey/DeleteValue/SetValue), which the
#: adapter records verbatim as ``event.action``.
_REGISTRY_FIELDS: MappingProxyType[str, str] = MappingProxyType(
    {
        "Image": "process.executable",
        "TargetObject": "registry.path",
        "Details": "registry.data",
        "EventType": "event.action",
    }
)

#: ``(product, category)`` → Sigma field name → our dotted ``field_path``.
FIELD_MAPS: MappingProxyType[tuple[str, str], MappingProxyType[str, str]] = MappingProxyType(
    {
        ("windows", "process_creation"): MappingProxyType(
            {
                "Image": "process.executable",
                "CommandLine": "process.command_line",
                "ParentImage": "process.parent_executable",
                "ParentCommandLine": "process.parent_command_line",
                "CurrentDirectory": "process.working_directory",
                "IntegrityLevel": "process.integrity_level",
                "OriginalFileName": "process.pe.original_file_name",
                "Description": "process.pe.description",
                "Product": "process.pe.product",
                "Company": "process.pe.company",
            }
        ),
        ("windows", "process_termination"): MappingProxyType(
            {"Image": "process.executable", "ProcessId": "process.pid"}
        ),
        ("windows", "network_connection"): MappingProxyType(
            {
                "Image": "process.executable",
                "DestinationIp": "network.destination.ip",
                "DestinationPort": "network.destination.port",
                "SourceIp": "network.source.ip",
                "SourcePort": "network.source.port",
                "Protocol": "network.transport",
            }
        ),
        ("windows", "image_load"): MappingProxyType(
            {
                "Image": "process.executable",
                "ImageLoaded": "dll.path",
                "OriginalFileName": "dll.pe.original_file_name",
                "Description": "dll.pe.description",
                "Product": "dll.pe.product",
                "Company": "dll.pe.company",
                "Signed": "dll.code_signature.signed",
                "Signature": "dll.code_signature.subject_name",
                "SignatureStatus": "dll.code_signature.status",
            }
        ),
        ("windows", "file_event"): MappingProxyType(
            {
                "Image": "process.executable",
                "TargetFilename": "file.path",
            }
        ),
        ("windows", "registry_add"): _REGISTRY_FIELDS,
        ("windows", "registry_delete"): _REGISTRY_FIELDS,
        ("windows", "registry_set"): _REGISTRY_FIELDS,
        ("windows", "registry_event"): _REGISTRY_FIELDS,
        ("windows", "process_access"): MappingProxyType(
            {
                "SourceImage": "process.executable",
                "TargetImage": "target_process.executable",
                "GrantedAccess": "process_access.granted_access",
                "CallTrace": "process_access.call_trace",
            }
        ),
        ("windows", "create_remote_thread"): MappingProxyType(
            {
                "SourceImage": "process.executable",
                "TargetImage": "target_process.executable",
                "StartAddress": "remote_thread.start_address",
                "StartModule": "remote_thread.start_module",
                "StartFunction": "remote_thread.start_function",
            }
        ),
        ("windows", "create_stream_hash"): MappingProxyType(
            {
                "Image": "process.executable",
                "TargetFilename": "file.path",
                "Contents": "file_stream.contents",
                "Hash": "file_stream.hashes",
            }
        ),
        ("windows", "file_delete"): MappingProxyType(
            {
                "Image": "process.executable",
                "TargetFilename": "file.path",
            }
        ),
        ("windows", "pipe_created"): MappingProxyType(
            {
                "Image": "process.executable",
                "PipeName": "pipe.name",
            }
        ),
        ("windows", "wmi_event"): MappingProxyType(
            {
                "Operation": "wmi.operation",
                "Name": "wmi.name",
                "EventNamespace": "wmi.namespace",
                "Query": "wmi.query",
                "Type": "wmi.consumer_type",
                "Destination": "wmi.destination",
                "Filter": "wmi.filter",
                "Consumer": "wmi.consumer",
            }
        ),
        ("windows", "ps_script"): MappingProxyType(
            {
                "ScriptBlockText": "powershell.script_block_text",
                "Path": "powershell.script_path",
            }
        ),
        ("windows", "ps_module"): MappingProxyType(
            {
                "Payload": "powershell.payload",
                "ContextInfo": "powershell.context_info",
            }
        ),
        ("windows", "dns_query"): MappingProxyType(
            {
                "Image": "process.executable",
                "QueryName": "dns.question_name",
                "QueryStatus": "dns.query_status",
                "QueryResults": "dns.results",
            }
        ),
        # Sysmon for Linux field names (ADR-0010 D3): POSIX paths as logged;
        # ``User`` is the plain account name (no DOMAIN\ part on Linux).
        ("linux", "process_creation"): MappingProxyType(
            {
                "Image": "process.executable",
                "CommandLine": "process.command_line",
                "ParentImage": "process.parent_executable",
                "ParentCommandLine": "process.parent_command_line",
                "CurrentDirectory": "process.working_directory",
                "User": "user.name",
            }
        ),
        ("linux", "file_event"): MappingProxyType(
            {"Image": "process.executable", "TargetFilename": "file.path"}
        ),
        ("linux", "network_connection"): MappingProxyType(
            {
                "Image": "process.executable",
                "DestinationIp": "network.destination.ip",
                "DestinationPort": "network.destination.port",
                "SourceIp": "network.source.ip",
                "SourcePort": "network.source.port",
                "Protocol": "network.transport",
            }
        ),
        ("windows", "security"): MappingProxyType(
            {
                "EventID": "event.code",
                "Provider_Name": "event.provider",
                "SubjectUserName": "user.name",
                "SubjectUserSid": "user.id",
                "SubjectDomainName": "user.domain",
                "TargetUserName": "target_user.name",
                "TargetUserSid": "target_user.id",
                "TargetDomainName": "target_user.domain",
                "LogonType": "logon.logon_type",
                "LogonProcessName": "logon.logon_process",
                "AuthenticationPackageName": "logon.authentication_package",
                "PackageName": "logon.package_name",
                "LmPackageName": "logon.lm_package",
                "KeyLength": "logon.key_length",
                "ImpersonationLevel": "logon.impersonation_level",
                "ElevatedToken": "logon.elevated_token",
                "TargetLogonId": "logon.logon_id",
                "WorkstationName": "logon.workstation_name",
                "Workstation": "logon.workstation",
                "Status": "logon.status",
                "SubStatus": "logon.sub_status",
                "TargetOutboundUserName": "logon.target_outbound_user_name",
                "IpAddress": "network.source.ip",
                "IpPort": "network.source.port",
                "ObjectServer": "object_access.server",
                "ObjectType": "object_access.type",
                "ObjectName": "object_access.name",
                "HandleId": "object_access.handle_id",
                "AccessMask": "object_access.access_mask",
                "AccessList": "object_access.access_list",
                "ObjectValueName": "object_access.value_name",
                "NewValue": "object_access.new_value",
                "ProcessName": "process.executable",
                "NewProcessName": "process.executable",
                "ParentProcessName": "process.parent_executable",
                "CommandLine": "process.command_line",
                "ShareName": "share.name",
                "ShareLocalPath": "share.local_path",
                "RelativeTargetName": "share.relative_target_name",
                # batch B
                "FailureReason": "logon.failure_reason",
                "TargetServerName": "logon.target_server_name",
                "TargetInfo": "logon.target_info",
                "SubjectLogonId": "logon.subject_logon_id",
                "TargetSid": "target_user.id",
                "PrivilegeList": "privilege.privilege_list",
                "Service": "privilege.service",
                "ServiceName": "service.name",
                "ServiceSid": "service.id",
                "ServiceFileName": "service.file_name",
                "ServiceType": "service.type",
                "ServiceStartType": "service.start_type",
                "ServiceAccount": "service.account",
                "ClientProcessId": "process.pid",
                "ParentProcessId": "process.parent_pid",
                "TicketOptions": "kerberos.ticket_options",
                "TicketEncryptionType": "kerberos.ticket_encryption_type",
                "PreAuthType": "kerberos.pre_auth_type",
                "CertThumbprint": "kerberos.cert_thumbprint",
                "TaskName": "scheduled_task.name",
                "TaskContent": "scheduled_task.content",
                "TaskContentNew": "scheduled_task.content_new",
                "OldValue": "object_access.old_value",
                "NewValueType": "object_access.new_value_type",
                "OldValueType": "object_access.old_value_type",
                "OperationType": "object_access.operation_type",
                "Properties": "object_access.properties",
                "AdditionalInfo": "object_access.additional_info",
                "SamAccountName": "account_change.sam_account_name",
                "UserPrincipalName": "account_change.user_principal_name",
                "DisplayName": "account_change.display_name",
                "OldUacValue": "account_change.old_uac_value",
                "NewUacValue": "account_change.new_uac_value",
                "UserAccountControl": "account_change.user_account_control",
                "SidHistory": "account_change.sid_history",
                "PrimaryGroupId": "account_change.primary_group_id",
                "MemberName": "account_change.member_name",
                "MemberSid": "account_change.member_sid",
                "TargetName": "credential_read.target_name",
                "ReadOperation": "credential_read.read_operation",
                "CountOfCredentialsReturned": "credential_read.count_returned",
                "ReturnCode": "credential_read.return_code",
                "FilterName": "wfp_filter.name",
                "FilterKey": "wfp_filter.key",
                "FilterType": "wfp_filter.type",
                "ChangeType": "wfp_filter.change_type",
                "ProviderName": "wfp_filter.provider_name",
                "ProviderContextName": "wfp_filter.provider_context_name",
                "LayerName": "wfp_filter.layer_name",
                "CalloutName": "wfp_filter.callout_name",
                "UserSid": "user.id",
            }
        ),
    }
)

#: Event-log channels whose rules select events by ``EventID``: the event IDs
#: an adapter really produces (must equal the adapter's own list — guarded by
#: a test). A conjunct pinned to any other ID is a telemetry gap: it could
#: never fire, and importing it would falsely count its technique as covered.
SUPPORTED_EVENT_CODES: MappingProxyType[tuple[str, str], frozenset[str]] = MappingProxyType(
    {
        ("windows", "security"): frozenset(
            {
                *("4624", "4656", "4658", "4663", "4688", "4776", "5140", "5145"),
                # batch B
                *("4611", "4625", "4648", "4657", "4661", "4662", "4672", "4673", "4674"),
                *("4697", "4698", "4702", "4720", "4722", "4724", "4728", "4732", "4738"),
                *("4768", "4769", "4771", "5379", "5441", "5447"),
            }
        ),
    }
)

#: Fields whose telemetry value is an *unrendered* Windows message reference
#: list (``%%4417 %%4418 …``), exactly as the event records it. Sigma content
#: is inconsistent here: some rules match the codes, others the rendered names
#: (``WriteData``). A rendered-name literal can never match real telemetry, so
#: its conjunct is a telemetry gap — imported, it would falsely count as
#: coverage. (No rendering table is guessed: the codes are what is logged.)
CODED_VALUE_FIELDS: MappingProxyType[tuple[str, str], frozenset[str]] = MappingProxyType(
    {
        ("windows", "security"): frozenset(
            {
                "object_access.access_list",
                "logon.impersonation_level",
                "logon.elevated_token",
                # batch B: logged as %%NNNN references
                "logon.failure_reason",
                "object_access.new_value_type",
                "object_access.old_value_type",
                "wfp_filter.type",
                "wfp_filter.change_type",
                "account_change.user_account_control",
                "credential_read.read_operation",
            }
        ),
    }
)

#: Why notable Sigma fields are deliberately unmapped (report text only).
UNMAPPED_FIELD_REASONS: MappingProxyType[str, str] = MappingProxyType(
    {
        "Hashes": (
            "Sigma matches Sysmon's combined 'SHA1=..,MD5=..,IMPHASH=..' string (often "
            "IMPHASH, which no adapter captures); no exact mapping onto structured hashes"
        ),
        "User": "UserRef splits domain and name; Sigma matches the combined 'DOMAIN\\user' string",
        "ParentUser": "the parent process's user is not captured",
        "DestinationHostname": "destination hostname is not captured on NetworkInfo",
        "Data": (
            "classic 'Windows PowerShell' channel (400/600/800) rules read the event's Data "
            "element; exports seen so far carry only the rendered Message"
        ),
        "SourceUser": "the acting process's user is not captured for process access",
        "SourceParentImage": "Sysmon 8 carries no source-parent image",
        "SourceCommandLine": "Sysmon 8 carries no source command line",
        "Initiated": "Sysmon 'Initiated' → ECS network.direction mapping is not verified",
    }
)

__all__ = [
    "FIELD_MAP_VERSION",
    "LOGSOURCE_SCOPES",
    "FIELD_MAPS",
    "SUPPORTED_EVENT_CODES",
    "PRODUCT_OS_SCOPES",
    "CODED_VALUE_FIELDS",
    "UNMAPPED_FIELD_REASONS",
]
