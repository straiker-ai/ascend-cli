"""
Targets that publish their own contract.

Probing a bare endpoint finds *a* body the target accepts, which is not the same as the body its
own client sends. A minimal `{"message": …}` earns a 200 and a sensible answer while leaving out
the fields that decide what is actually under test — which workspace, which tools are live, whose
guardrail key the turn is scored against. The run that follows is green and measures the wrong
agent.

Some applications remove the guesswork: they expose an endpoint (or a "point Ascend here" panel)
that states the contract outright. A person onboarding that target would read it before doing
anything else. This module does the same, first, and falls back to probing only when the target
says nothing about itself.

A profile is three functions and no state:

    detect(origin)   -> is this that application? (unauthenticated, one GET)
    inspect(origin)  -> what it is, what it needs from the operator, what can be targeted
    build(origin, …) -> the adapter config, in the same shape probing produces

Nothing here stores a credential. Values pass through into the config exactly as a probed
target's would.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

TIMEOUT = 20


def origin_of(url: str) -> str:
    p = urlparse(url if "//" in str(url) else f"https://{url}")
    return f"{p.scheme or 'https'}://{p.netloc}"


def _is_power_platform_error(body: Any) -> bool:
    """The Power Platform API error contract: {"error": {"code": ..., "message": ...}}.

    A 401/403 alone proves nothing about WHICH platform answered. Any host with an access gate
    (a passcode page, a WAF, basic auth) 401s on an arbitrary path too, and treating that as a
    Copilot Studio signal claimed an unrelated host for this profile — MEASURED on a gated lab
    target: "misfingerprinted as Copilot Studio", registration refused. What a real Entra-gated
    agent's token endpoint returns is this JSON shape; a passcode page returns HTML, a generic
    gate returns a string error. Only the contract is evidence.
    """
    return (isinstance(body, dict) and isinstance(body.get("error"), dict)
            and bool(body["error"].get("code")))


def _get(url: str, headers: Optional[Dict[str, str]] = None, verify: bool = True) -> Tuple[int, Any]:
    try:
        r = requests.get(url, headers=headers or {}, timeout=TIMEOUT, verify=verify)
    except requests.RequestException:
        return 0, None
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, None


# --------------------------------------------------------------------------- Doppelganger
class Doppelganger:
    """Straiker's multi-vertical agentic demo host.

    One origin serves several workspaces (verticals), each its own agent with its own system
    prompt and tools. Access takes a passcode header; every turn must also carry a Straiker
    Defend key, which decides whose tenant scores it. The contract below mirrors the app's own
    "Point Ascend at this agent" panel field for field.
    """

    name = "doppelganger"
    label = "Doppelganger"

    @staticmethod
    def detect(origin: str, verify: bool = True) -> bool:
        status, body = _get(f"{origin}/api/config", verify=verify)
        return status == 200 and isinstance(body, dict) and body.get("app_name") == "Doppelganger"

    @staticmethod
    def needs() -> List[Dict[str, str]]:
        return [
            {"name": "x-demo-key", "kind": "header",
             "why": "the access passcode for this host"},
            {"name": "apiKey", "kind": "body",
             "why": "a Straiker Defend key — every turn is scored against the tenant it belongs to"},
        ]

    @classmethod
    def workspaces(cls, origin: str, headers: Dict[str, str], verify: bool = True) -> List[Dict[str, Any]]:
        status, body = _get(f"{origin}/api/workspaces", headers=headers, verify=verify)
        rows = (body or {}).get("workspaces") if isinstance(body, dict) else body
        return [w for w in (rows or []) if isinstance(w, dict)] if status == 200 else []

    @classmethod
    def inspect(cls, origin: str, headers: Dict[str, str], verify: bool = True) -> Dict[str, Any]:
        rows = cls.workspaces(origin, headers, verify)
        return {
            "profile": cls.name, "label": cls.label, "origin": origin,
            "endpoint": f"{origin}/api/chat",
            "needs": cls.needs(),
            "choose": "workspace",
            "workspaces": [{"slug": w.get("slug"), "name": w.get("name"),
                            "description": w.get("description")} for w in rows],
            "note": ("One origin, several agents. Each workspace is a separate target and should "
                     "be registered as its own application."),
        }

    @classmethod
    def build(cls, origin: str, *, workspace: str, headers: Dict[str, str],
              body_fields: Dict[str, Any], bearer: Optional[str] = None,
              verify: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """(config, facts). Raises ValueError naming exactly what is missing."""
        hdrs = {k: v for k, v in (headers or {}).items()}
        low = {k.lower(): v for k, v in hdrs.items()}
        key = body_fields.get("apiKey") or bearer or ""
        if not key and low.get("authorization", "").lower().startswith("bearer "):
            key = low["authorization"][7:].strip()
        missing = []
        if not low.get("x-demo-key"):
            missing.append("the access passcode (header x-demo-key)")
        if not key:
            missing.append("a Straiker Defend key (body field apiKey)")
        if missing:
            raise ValueError("this is a Doppelganger host and it needs " + " and ".join(missing))
        if not workspace:
            slugs = ", ".join(str(w.get("slug")) for w in cls.workspaces(origin, hdrs, verify))
            raise ValueError(f"this host serves several agents — choose one with --workspace "
                             f"({slugs or 'list them with `ascend target inspect`'})")

        status, ws = _get(f"{origin}/api/workspaces/{workspace}", headers=hdrs, verify=verify)
        if status != 200 or not isinstance(ws, dict):
            raise ValueError(f"workspace {workspace!r} was not found on {origin} (HTTP {status})")

        send = {k: v for k, v in hdrs.items() if k.lower() != "authorization"}
        send.setdefault("Content-Type", "application/json")
        body = {
            "message": "{{PROMPT}}",
            "apiKey": key,
            # The share token, not the slug: it is what the app's own panel emits.
            "workspace": ws.get("share_id") or ws.get("slug") or workspace,
            "userName": body_fields.get("userName") or "ascend",
            "activeConnectors": body_fields.get("activeConnectors") or [],
            "connectorCredentials": {},
            "llmProvider": body_fields.get("llmProvider") or (ws.get("llm") or {}).get("provider") or "bedrock",
            "llmKey": None,
            "systemPrompt": None,
            "ragContent": None,
        }
        cfg = {
            "adapter": "direct_api",
            "endpoint": f"{origin}/api/chat",
            "method": "POST",
            "headers": send,
            "body": body,
            "response_path": "message",
            "_profile": cls.name,
        }
        tools = [t.get("name") for t in (ws.get("tool_specs") or []) if isinstance(t, dict)]
        facts = {
            "profile": cls.name,
            "name": f"Doppelganger · {ws.get('name') or workspace}",
            "workspace": ws.get("slug") or workspace,
            "system_prompt": ws.get("system_prompt") or "",
            "purpose": ws.get("description") or "",
            "tools": tools,
            "agentic": bool(tools),
        }
        return cfg, facts


# --------------------------------------------------------------------- Copilot Studio
# The Power Platform API host per cloud. Read from
# microsoft-agents-copilotstudio-client 1.2.0, `PowerPlatformEnvironment.get_endpoint_suffix`,
# not from memory. Only the clouds an assessment realistically runs against are listed;
# an unknown cloud is rejected by name rather than guessed at.
PP_API_SUFFIX = {
    "PROD": "api.powerplatform.com",
    "FIRST_RELEASE": "api.powerplatform.com",
    "GOV": "api.gov.powerplatform.microsoft.us",
    "GOV_FR": "api.gov.powerplatform.microsoft.us",
    "HIGH": "api.high.powerplatform.microsoft.us",
    "DOD": "api.appsplatform.us",
    "MOONCAKE": "api.powerplatform.partner.microsoftonline.cn",
}
# The environment id's last N hex digits become their own DNS label. Two for the
# commercial clouds, one everywhere else — same source as above (`get_id_suffix_length`).
PP_SUFFIX_LEN = {"PROD": 2, "FIRST_RELEASE": 2}


class CopilotStudio:
    """A Microsoft Copilot Studio agent.

    What it publishes is its address, not a panel: the URL encodes the Power Platform
    environment and the agent, so the callable endpoint is *derived*, never typed. That
    matters more here than anywhere else, because a tenant has hundreds of these and the
    per-agent value is the difference between one click and one portal visit each.

    Two families, told apart by one unauthenticated GET of the Direct Line token endpoint:

      A. 200 with a token — the agent's Security is "No authentication". Anyone who can
         reach the URL can talk to it, which is itself worth reporting.
      B. 401/403 — the agent is Entra-gated. The anonymous token endpoint does not exist
         for it and the reachable surface is the Power Platform conversations API, which
         needs an Entra token (audience https://api.powerplatform.com/.default) and the
         agent's schema name. The schema name is the one thing the address cannot yield.
    """

    name = "copilot_studio"
    label = "Microsoft Copilot Studio"

    API_VERSION = "2022-03-01-preview"
    TOKEN_PATH = "/copilotstudio/directline/token"
    DIRECTLINE_GLOBAL = "https://directline.botframework.com"
    INVOKE_SCOPE = "https://api.powerplatform.com/.default"

    # ---------------------------------------------------------------- addressing
    @staticmethod
    def environment_host(environment_id: str, cloud: str = "PROD") -> str:
        """The environment's API host, derived from its id.

        A mirror of the M365 Agents SDK's own derivation. This is the finding that makes
        one click possible: an enumerated agent needs no portal visit to become callable,
        because its host is a pure function of the environment id.
        """
        cloud = (cloud or "PROD").upper()
        if cloud not in PP_API_SUFFIX:
            raise ValueError(f"unknown Power Platform cloud {cloud!r}; "
                             f"known: {', '.join(sorted(PP_API_SUFFIX))}")
        norm = str(environment_id).lower().replace("-", "")
        if len(norm) != 32 or any(c not in "0123456789abcdef" for c in norm):
            raise ValueError(f"environment id {environment_id!r} is not a GUID")
        n = PP_SUFFIX_LEN.get(cloud, 1)
        return f"{norm[:-n]}.{norm[-n:]}.environment.{PP_API_SUFFIX[cloud]}"

    @classmethod
    def environment_id_from_host(cls, host: str) -> Optional[str]:
        """The environment id back out of a host, or None. The inverse of the above."""
        labels = str(host).split(".")
        if len(labels) < 3 or labels[2] != "environment":
            return None
        norm = (labels[0] + labels[1]).lower()
        if len(norm) != 32 or any(c not in "0123456789abcdef" for c in norm):
            return None
        return (f"{norm[0:8]}-{norm[8:12]}-{norm[12:16]}-{norm[16:20]}-{norm[20:32]}")

    @classmethod
    def conversations_url(cls, environment_id: str, schema_name: str, *,
                          cloud: str = "PROD", published: bool = True,
                          conversation_id: Optional[str] = None) -> str:
        """The Power Platform conversations endpoint for one agent (Family B)."""
        if not schema_name:
            raise ValueError("a schema name is required to address a Copilot Studio agent")
        host = cls.environment_host(environment_id, cloud)
        kind = "dataverse-backed" if published else "prebuilt"
        path = f"/copilotstudio/{kind}/authenticated/bots/{schema_name}/conversations"
        if conversation_id:
            path = f"{path}/{conversation_id}"
        return f"https://{host}{path}?api-version={cls.API_VERSION}"

    @classmethod
    def token_url(cls, origin: str) -> str:
        return f"{origin}{cls.TOKEN_PATH}?api-version={cls.API_VERSION}"

    @classmethod
    def is_power_platform_host(cls, origin: str) -> bool:
        host = urlparse(origin).netloc.split(":")[0].lower()
        return any(host.endswith(f".environment.{s}") for s in set(PP_API_SUFFIX.values()))

    # ---------------------------------------------------------------- the profile
    @classmethod
    def detect(cls, origin: str, verify: bool = True) -> bool:
        """Recognised by its host, or by answering the token endpoint at all.

        The host check costs nothing and settles every real tenant. The GET exists so a
        self-hosted stand-in serving the same contract is recognised too — which is the
        only way any of this is testable without a Microsoft tenant.
        """
        if cls.is_power_platform_host(origin):
            return True
        status, body = _get(cls.token_url(origin), verify=verify)
        if status in (401, 403):
            return _is_power_platform_error(body)
        return status == 200 and isinstance(body, dict) and bool(body.get("token"))

    @classmethod
    def family(cls, origin: str, verify: bool = True) -> str:
        """'directline', 'entra', or 'unknown' — from the token endpoint's answer."""
        status, body = _get(cls.token_url(origin), verify=verify)
        if status == 200 and isinstance(body, dict) and body.get("token"):
            return "directline"
        # On a real Power Platform host the host is the evidence; anywhere else the 401 must
        # carry the Power Platform error contract to count (see _is_power_platform_error).
        if status in (401, 403) and (cls.is_power_platform_host(origin) or _is_power_platform_error(body)):
            return "entra"
        return "unknown"

    @classmethod
    def needs(cls, family: str = "unknown") -> List[Dict[str, str]]:
        if family == "directline":
            return [{"name": "(nothing)", "kind": "none",
                     "why": "this agent's Security is 'No authentication' — its token "
                            "endpoint hands out a Direct Line token to anyone who asks"}]
        return [
            {"name": "schema_name", "kind": "config",
             "why": "names the agent inside the environment; it is the one value the "
                    "address cannot be derived from (Settings > Advanced > Metadata)"},
            {"name": "environment_id", "kind": "config",
             "why": "the Power Platform environment; derivable from the host if the URL "
                    "already points at one"},
            {"name": "ASCEND_ENTRA_TOKEN", "kind": "env",
             "why": f"an Entra token for {cls.INVOKE_SCOPE} (CopilotStudio.Copilots.Invoke). "
                    "One app registration serves every agent in the tenant"},
        ]

    @classmethod
    def inspect(cls, origin: str, headers: Dict[str, str], verify: bool = True) -> Dict[str, Any]:
        fam = cls.family(origin, verify)
        env_id = cls.environment_id_from_host(urlparse(origin).netloc.split(":")[0])
        out: Dict[str, Any] = {
            "profile": cls.name, "label": cls.label, "origin": origin,
            "family": fam,
            "environment_id": env_id,
            "needs": cls.needs(fam),
            "choose": None if fam == "directline" else "schema_name",
            "workspaces": [],
        }
        if fam == "directline":
            out["endpoint"] = cls.token_url(origin)
            out["note"] = ("The agent answers anyone who can reach it: its token endpoint "
                           "is unauthenticated. Nothing further is needed to test it, and "
                           "that it is open at all belongs in the report.")
        elif fam == "entra":
            out["endpoint"] = (cls.conversations_url(env_id, "{schema_name}")
                               if env_id else None)
            out["note"] = ("Entra-gated. One tenant-wide app registration with "
                           "CopilotStudio.Copilots.Invoke reaches every agent here; only "
                           "the schema name changes per agent.")
        else:
            out["note"] = ("A Copilot Studio host, but its token endpoint answered neither "
                           "a token nor an auth challenge. Confirm the URL before wiring it.")
        return out

    @classmethod
    def build(cls, origin: str, *, workspace: Optional[str] = None,
              headers: Optional[Dict[str, str]] = None,
              body_fields: Optional[Dict[str, Any]] = None,
              bearer: Optional[str] = None, verify: bool = True):
        """(config, facts). Raises ValueError naming exactly what is missing.

        `workspace` carries the agent's schema name, which is what one address serves
        several of here — the same role a workspace slug plays on a multi-agent host.
        """
        fields = dict(body_fields or {})
        fam = fields.get("family") or cls.family(origin, verify)
        host = urlparse(origin).netloc.split(":")[0]
        cloud = str(fields.get("cloud") or "PROD").upper()

        if fam == "directline":
            # A Power Platform host mints tokens for the global Direct Line service; any
            # other host answering this contract is serving Direct Line itself.
            base = fields.get("directline_base") or (
                cls.DIRECTLINE_GLOBAL if cls.is_power_platform_host(origin) else origin)
            cfg = {
                "adapter": "copilot_studio",
                "endpoint": cls.token_url(origin),
                "directline_token_endpoint": cls.token_url(origin),
                "directline_base": base.rstrip("/"),
                "user_id": fields.get("user_id") or "dl_ascend",
                "warmup_message": fields.get("warmup_message", "Hello"),
                "_profile": cls.name,
            }
            facts = {
                "profile": cls.name,
                "name": f"Copilot Studio · {workspace or host.split('.')[0]}",
                "workspace": workspace or "(unauthenticated agent)",
                "system_prompt": "",
                "purpose": "Microsoft Copilot Studio agent, Direct Line 3.0, no authentication",
                "tools": [],
                "agentic": False,
                "family": "directline",
            }
            return cfg, facts

        if fam != "entra":
            raise ValueError(
                f"{origin} did not answer the Copilot Studio token endpoint with either a "
                "token or an auth challenge, so its family is unknown — check the URL")

        env_id = fields.get("environment_id") or cls.environment_id_from_host(host)
        missing = []
        if not env_id:
            missing.append("the environment id (--field environment_id=<guid>)")
        if not workspace:
            missing.append("the agent's schema name (--workspace <schema>, from "
                           "Settings > Advanced > Metadata)")
        token = bearer or fields.get("entra_token")
        token_env = fields.get("entra_token_env") or "ASCEND_ENTRA_TOKEN"
        if not token and not os.environ.get(token_env):
            missing.append(f"an Entra token for {cls.INVOKE_SCOPE} "
                           f"(env {token_env}, or --bearer)")
        if missing:
            raise ValueError("this is an Entra-gated Copilot Studio agent and it needs "
                             + " and ".join(missing))

        url = cls.conversations_url(env_id, workspace, cloud=cloud)
        send = {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"}
        send["Content-Type"] = "application/json"
        send["Accept"] = "text/event-stream"
        cfg = {
            # Two POSTs where the second's URL carries an id from the first's response,
            # and the answer streams. That is a session, not a request.
            "adapter": "session_api",
            "endpoint": url,
            "environment_id": env_id,
            "schema_name": workspace,
            "cloud": cloud,
            "method": "POST",
            "headers": send,
            "body": {"activity": {"type": "message", "text": "{{PROMPT}}"}},
            "session": {
                "url": url,
                "method": "POST",
                "body": {"emitStartConversationEvent": True},
                "id_from_header": "x-ms-conversationid",
                "id_path": "conversation.id",
                "url_template": cls.conversations_url(env_id, workspace, cloud=cloud,
                                                      conversation_id="{{SESSION}}"),
            },
            "stream": "sse",
            "response_path": "text",
            "auth": {"type": "static", "token_env": token_env},
            "_profile": cls.name,
        }
        if token:
            cfg["headers"]["Authorization"] = f"Bearer {token}"
        facts = {
            "profile": cls.name,
            "name": f"Copilot Studio · {workspace}",
            "workspace": workspace,
            "system_prompt": "",
            "purpose": "Microsoft Copilot Studio agent, Entra-gated, Power Platform "
                       "conversations API",
            "tools": [],
            "agentic": False,
            "family": "entra",
            "environment_id": env_id,
        }
        return cfg, facts


class OpenAICompatible:
    """A server that speaks the OpenAI chat completions contract: OpenAI, Azure OpenAI, LiteLLM,
    vLLM, Ollama, enterprise gateways. Detected by `GET {origin}/v1/models`: a model list, or an
    OpenAI-shaped error object (401 without a key is the common case) both say the contract is
    there. The chat URL is the one the operator gave when it already ends in `/chat/completions`
    (Azure's deployment path, a gateway's prefix), else `{origin}/v1/chat/completions`."""
    name = "openai_compatible"
    label = "OpenAI-compatible API"

    @staticmethod
    def detect(origin: str, verify: bool = True) -> bool:
        status, body = _get(f"{origin}/v1/models", verify=verify)
        if status == 200 and isinstance(body, dict) and isinstance(body.get("data"), list):
            return True
        return status in (401, 403) and isinstance(body, dict) and isinstance(body.get("error"), (dict, str))

    @classmethod
    def build(cls, origin: str, *, workspace: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
              body_fields: Optional[Dict[str, Any]] = None, bearer: Optional[str] = None,
              verify: bool = True, url: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        from adapters.openai_compatible import chat_url  # noqa: PLC0415
        endpoint = chat_url(url or origin)
        cfg: Dict[str, Any] = {"adapter": "openai_compatible", "endpoint": endpoint, "verify_tls": verify,
                               "_comment": "OpenAI-compatible chat completions; `model` is asked of the server when unset"}
        if headers:
            cfg["headers"] = dict(headers)
        for key in ("model", "system_prompt", "max_tokens"):
            if body_fields and body_fields.get(key) is not None:
                cfg[key] = body_fields[key]
        host = urlparse(origin).netloc.split(":")[0]
        facts = {"workspace": host, "tools": [], "name": f"{host.split('.')[0]}-chat",
                 "purpose": f"OpenAI-compatible chat completions at {endpoint}", "system_prompt": ""}
        return cfg, facts


class DialogflowCX:
    """A Dialogflow CX agent, addressed by its agent URL; recognised from the host alone."""
    name = "dialogflow_cx"
    label = "Dialogflow CX"

    @staticmethod
    def detect(origin: str, verify: bool = True) -> bool:
        host = urlparse(origin).netloc.split(":")[0].lower()
        return host.endswith("dialogflow.googleapis.com")

    @classmethod
    def build(cls, origin: str, *, workspace: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
              body_fields: Optional[Dict[str, Any]] = None, bearer: Optional[str] = None,
              verify: bool = True, url: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if not url or "/agents/" not in url:
            raise ValueError("a Dialogflow CX target needs its agent URL "
                             "(…/v3/projects/{p}/locations/{l}/agents/{a}); the origin alone names no agent")
        cfg: Dict[str, Any] = {"adapter": "dialogflow_cx", "endpoint": url.split("?", 1)[0], "verify_tls": verify,
                               "_comment": "Dialogflow CX detectIntent; one session per prompt"}
        if headers:
            cfg["headers"] = dict(headers)
        if body_fields and body_fields.get("language_code"):
            cfg["language_code"] = body_fields["language_code"]
        agent = url.split("/agents/", 1)[1].split("/", 1)[0].split("?", 1)[0]
        facts = {"workspace": urlparse(origin).netloc, "tools": [], "name": f"dialogflow-{agent[:12]}",
                 "purpose": f"Dialogflow CX agent {agent}", "system_prompt": ""}
        return cfg, facts


PROFILES = [Doppelganger, CopilotStudio, OpenAICompatible, DialogflowCX]


def detect(url: str, verify: bool = True):
    """The profile for this target, or None. Costs one unauthenticated GET per known profile."""
    origin = origin_of(url)
    for prof in PROFILES:
        try:
            if prof.detect(origin, verify=verify):
                return prof
        except Exception:
            continue
    return None
