"""Tool schemas handed to the model.

Authored once in Anthropic tool-use shape (CLAUDE.md section 2) with a
converter to OpenAI function-calling shape, because the configured gateway
exposes both surfaces. The schema text is prompt surface: each description
tells the agent what the tool is *for* and, where it matters, what it
deliberately will not do for it.
"""
from __future__ import annotations

from typing import Any

FACTOR_ENUM = [
    "version_in_range",
    "logs_consistent",
    "exfil_indicators",
    "related_alert_corroborates",
    "version_patched",
    "logs_clean",
    "packet_benign",
]

ANTHROPIC_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_alert",
        "description": (
            "Retrieve the raw NIDS alert record: signature, source and destination "
            "IP, target asset id, and the sensor's severity_label. The severity_label "
            "is the sensor's opinion, not a finding. It is not evidence that the "
            "attack succeeded."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"alert_id": {"type": "string", "description": "e.g. ALERT-2001"}},
            "required": ["alert_id"],
        },
    },
    {
        "name": "get_packet_metadata",
        "description": (
            "Flow-level metadata for the alert: bytes transferred in each direction, "
            "duration, protocol anomalies, payload entropy and an exfil_indicators "
            "flag. Use this to tell an attempt that returned an error page from one "
            "that returned megabytes of data."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"alert_id": {"type": "string"}},
            "required": ["alert_id"],
        },
    },
    {
        "name": "get_asset_info",
        "description": (
            "Inventory record for the targeted host: criticality, OS, and the "
            "service_versions actually running on it. The running version is what "
            "you need to decide whether a CVE applies to this host."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"asset_id": {"type": "string", "description": "e.g. SRV-DB-02"}},
            "required": ["asset_id"],
        },
    },
    {
        "name": "get_configuration",
        "description": (
            "Configuration surfaces on the host: WAF posture, database account "
            "grants, egress filtering. This is the CONTROL layer - a host can be "
            "running a vulnerable version and still be impossible to exploit "
            "because a control sits in the way. Like the CVE knowledge base, this "
            "source does NOT tell you whether the attack succeeded: it does not "
            "know what the alert was. Compare the surfaces against the attack "
            "class yourself and say which one blocks it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"asset_id": {"type": "string", "description": "e.g. SRV-HR-11"}},
            "required": ["asset_id"],
        },
    },
    {
        "name": "get_vulnerabilities",
        "description": (
            "CVE entries for a service name (e.g. 'mysql', 'apache', 'tomcat'), "
            "each with an affected_versions range, fixed_in, cvss and attack_class. "
            "This knowledge base does NOT know what any host is running and will "
            "NOT tell you whether a host is patched. You must compare the running "
            "version from get_asset_info against affected_versions yourself and say "
            "out loud which side of the range it falls on."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "Service name only, not a version. e.g. 'mysql'",
                }
            },
            "required": ["service_name"],
        },
    },
    {
        "name": "get_server_logs",
        "description": (
            "Host-side log entries (database queries, auth events, process spawns) "
            "for an asset. This is the primary source for whether the attack "
            "actually did anything on the host. May fail or be unavailable; if it "
            "does, that is a tool failure to be reported, NOT evidence of absence "
            "of an attack."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string"},
                "time_range": {
                    "type": "string",
                    "description": (
                        "Optional ISO-8601 window 'START/END', e.g. "
                        "'2026-09-11T03:00:00Z/2026-09-11T04:00:00Z'. Omit for all entries."
                    ),
                },
            },
            "required": ["asset_id"],
        },
    },
    {
        "name": "get_related_alerts",
        "description": (
            "Other alerts recorded against the same asset, together with their case "
            "ids and the conclusion already stored for those cases. Use this to find "
            "out whether this asset has a history that changes how you read the "
            "current alert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"asset_id": {"type": "string"}},
            "required": ["asset_id"],
        },
    },
    {
        "name": "check_firewall_state",
        "description": (
            "Read current firewall state for an IP from disk and report whether it "
            "is blocked. Use this to VERIFY that a block or unblock actually took "
            "effect, after you perform one."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "block_ip",
        "description": (
            "Add a DROP rule for an IP to the sandboxed firewall. This is a real "
            "state mutation inside the sandbox. Set precautionary=true when you are "
            "containing under uncertainty on a critical asset rather than acting on "
            "a confirmed verdict."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "reason": {
                    "type": "string",
                    "description": "Cite the evidence that justifies the block.",
                },
                "precautionary": {"type": "boolean", "default": False},
            },
            "required": ["ip", "reason"],
        },
    },
    {
        "name": "unblock_ip",
        "description": "Remove a DROP rule for an IP from the sandboxed firewall.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["ip", "reason"],
        },
    },
    {
        "name": "submit_assessment",
        "description": (
            "Submit your investigation findings once you have enough evidence to "
            "classify. Do NOT emit a confidence number or an outcome: you declare "
            "which evidence classes you found and cite them, and the scoring "
            "function computes the score and the outcome deterministically. "
            "Declare only factors you actually have a tool result for."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis": {
                    "type": "string",
                    "description": "The leading hypothesis you are concluding on.",
                },
                "factors": {
                    "type": "array",
                    "description": (
                        "Evidence classes you found. Omit any factor you did not "
                        "establish. Never declare both a finding and its negation. "
                        "A factor asserts that the finding IS TRUE - so declare "
                        "'related_alert_corroborates' only when another alert "
                        "actually corroborates, never when the lookup came back "
                        "empty. An empty or failed lookup establishes nothing and "
                        "must not be cited as a factor at all."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "factor": {
                                "type": "string", "enum": FACTOR_ENUM,
                                "description": (
                                    "version_in_range: the running version IS "
                                    "inside a CVE's affected range. "
                                    "version_patched: it is outside ALL affected "
                                    "ranges. "
                                    "logs_consistent: host logs show the attack "
                                    "ACTUALLY DID SOMETHING - a malicious query "
                                    "that executed, rows returned, a process "
                                    "spawned, an account created. An attempt that "
                                    "errored out, was blocked, or returned zero "
                                    "rows is NOT logs_consistent. "
                                    "logs_clean: logs show no successful attacker "
                                    "activity in the window - including the case "
                                    "where the attempt is visible but demonstrably "
                                    "failed. "
                                    "exfil_indicators / packet_benign: what the "
                                    "PACKET METADATA for this case's own alert "
                                    "shows - these two are grounded in "
                                    "get_packet_metadata only. Exfiltration you "
                                    "found in host logs (a dump piped to curl, "
                                    "say) is logs_consistent; counting it again "
                                    "as exfil_indicators scores one body of "
                                    "evidence twice. "
                                    "related_alert_corroborates: another alert on "
                                    "this asset actually corroborates."
                                ),
                            },
                            "citation": {
                                "type": "string",
                                "description": (
                                    "The specific tool result supporting this, quoted "
                                    "concretely. e.g. 'get_asset_info: SRV-DB-02 runs "
                                    "mysql 5.7.21; get_vulnerabilities: CVE-2023-21980 "
                                    "affects >=5.7.0,<5.7.30 - 5.7.21 is inside.'"
                                ),
                            },
                            "rationale": {"type": "string"},
                        },
                        "required": ["factor", "citation", "rationale"],
                    },
                },
                "sufficiency": {
                    "type": "string",
                    "description": (
                        "Why the evidence you have is sufficient to classify now, and "
                        "what you still do not know."
                    ),
                },
                "disconfirming_evidence_checked": {
                    "type": "string",
                    "description": (
                        "What evidence would FALSIFY your leading hypothesis, and "
                        "what you found when you went looking for it."
                    ),
                },
            },
            "required": ["hypothesis", "factors", "sufficiency"],
        },
    },
]

def _add_reason_param() -> None:
    """Make 'reason' a required argument on every tool except submit_assessment.

    CLAUDE.md section 9 requires the evidence chain to record "the agent's
    stated reason for each step". Making it a required tool parameter
    guarantees the trace has one for every call, instead of depending on the
    model volunteering narration alongside its tool calls.
    """
    for tool in ANTHROPIC_TOOLS:
        if tool["name"] == "submit_assessment":
            continue
        schema = tool["input_schema"]
        # block_ip / unblock_ip already declare `reason` - there it is a real
        # implementation parameter (the justification recorded in firewall
        # state), not just trace narration. Leave those alone: re-adding it
        # would clobber the description AND duplicate the entry in `required`,
        # which is invalid JSON Schema and is rejected by the gateway.
        if "reason" in schema["properties"]:
            continue
        schema["properties"]["reason"] = {
            "type": "string",
            "description": (
                "Why you are making THIS call right now: what you expect it to "
                "tell you, and how it advances or falsifies your hypothesis."
            ),
        }
        schema.setdefault("required", []).append("reason")


_add_reason_param()

# Tools available while gathering evidence vs. while acting on a conclusion.
GATHER_TOOLS = [
    "get_alert", "get_packet_metadata", "get_asset_info", "get_vulnerabilities",
    "get_configuration", "get_server_logs", "get_related_alerts", "check_firewall_state",
    "submit_assessment",
]
ACT_TOOLS = ["check_firewall_state", "block_ip", "unblock_ip"]


def anthropic_tools(names: list[str] | None = None) -> list[dict[str, Any]]:
    if names is None:
        return list(ANTHROPIC_TOOLS)
    return [t for t in ANTHROPIC_TOOLS if t["name"] in names]


def openai_tools(names: list[str] | None = None) -> list[dict[str, Any]]:
    """Convert to OpenAI function-calling shape."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in anthropic_tools(names)
    ]
