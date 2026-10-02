"""A host that 401s for its own reasons (an access-code page, a WAF, basic auth) is not Copilot
Studio. Only the Power Platform error contract on the token endpoint is evidence."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime.discovery import profiles  # noqa: E402

CS = profiles.CopilotStudio
ORIGIN = "https://gated-lab.example.test"


def test_a_passcode_page_401_is_not_copilot_studio(monkeypatch):
    monkeypatch.setattr(profiles, "_get", lambda *a, **kw: (401, None))          # HTML page: no JSON body
    assert CS.detect(ORIGIN) is False
    assert CS.family(ORIGIN) == "unknown"


def test_a_generic_json_401_is_not_copilot_studio(monkeypatch):
    monkeypatch.setattr(profiles, "_get", lambda *a, **kw: (401, {"error": "access code required"}))
    assert CS.detect(ORIGIN) is False


def test_the_power_platform_error_contract_still_is(monkeypatch):
    body = {"error": {"code": "Unauthorized", "message": "This agent requires authentication."}}
    monkeypatch.setattr(profiles, "_get", lambda *a, **kw: (401, body))
    assert CS.detect(ORIGIN) is True
    assert CS.family(ORIGIN) == "entra"


def test_a_real_environment_host_needs_no_body(monkeypatch):
    monkeypatch.setattr(profiles, "_get", lambda *a, **kw: (401, None))
    assert CS.detect("https://abc123.environment.api.powerplatform.com") is True
