"""The hand-over bundle: the adapter as a reusable artifact with no secret in it."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime")); sys.path.insert(0, str(ROOT))
import bundle  # noqa: E402

CFG = {"adapter": "direct_api", "endpoint": "https://lab.example.test/session/api/messages", "method": "POST",
       "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
       "headers": {"Content-Type": "application/json", "Origin": "https://lab.example.test"},
       "auth": {"type": "derived_multihop",
                "steps": [{"method": "POST", "url": "https://lab.example.test/session/api/conversations",
                           "headers": {"Cookie": "env:ASCEND_SECRET_LAB_COOKIE"}, "extract": [{"var": "MINTED_0", "path": "token"}]}],
                "attach": {"headers": {"X-Conv-Token": "{{MINTED_0}}", "Cookie": "env:ASCEND_SECRET_LAB_COOKIE"}}},
       "auth_lifecycle": {"type": "refresh_on_ttl", "ttl_s": 0},
       "_discovery": {"source": "url", "big": "x" * 5000}, "_withheld_headers": ["Cookie"]}


def test_bundle_has_the_parts_and_no_secret(tmp_path):
    m = bundle.write_bundle(CFG, tmp_path / "b", app_name="target-lab-session", app_id="aapp_1", tenant="123",
                            evidence={"har": "recordings/x.har"}, vendor_runtime=True)
    out = tmp_path / "b"
    for f in ("adapter.json", "manifest.json", "secrets.template.env", "README.md", "relay/Dockerfile", "relay/entrypoint.py",
              "shim/app.py", "shim/lambda_handler.py", "shim/Dockerfile", "shim/template.yaml", "vendor/runtime/call_target.py"):
        assert (out / f).exists(), f
    assert m["secrets_required"] == ["ASCEND_SECRET_LAB_COOKIE"]
    assert m["adapter"] == "direct_api" and m["app"] == {"name": "target-lab-session", "id": "aapp_1", "tenant": "123"}
    text = (out / "adapter.json").read_text() + (out / "README.md").read_text() + (out / "secrets.template.env").read_text()
    assert "x" * 100 not in text                                  # discovery bulk trimmed
    assert re.search(r"ASCEND_SECRET_LAB_COOKIE=\s*$", (out / "secrets.template.env").read_text(), re.M)   # named, never valued
    assert "env:ASCEND_SECRET_LAB_COOKIE" in (out / "adapter.json").read_text()


def test_a_literal_credential_header_is_turned_into_a_reference(tmp_path):
    cfg = dict(CFG, headers={"Content-Type": "application/json", "Cookie": "lab_access=REAL-VALUE-9f13"})
    bundle.write_bundle(cfg, tmp_path / "c", app_name="x", vendor_runtime=False)
    text = (tmp_path / "c" / "adapter.json").read_text()
    assert "REAL-VALUE-9f13" not in text and '"Cookie": "env:COOKIE"' in text


def test_same_config_same_hash(tmp_path):
    a = bundle.write_bundle(CFG, tmp_path / "a", app_name="x", vendor_runtime=False)
    b = bundle.write_bundle(json.loads(json.dumps(CFG)), tmp_path / "b", app_name="x", vendor_runtime=False)
    assert a["hash"] == b["hash"]


def test_env_refs_are_collected_from_anywhere_in_the_config():
    assert bundle.env_refs({"a": {"b": ["env:ONE", {"c": "env:TWO"}]}, "d": "env:ONE"}) == ["ONE", "TWO"]


def test_page_url_query_string_never_travels(tmp_path):
    """The page the browser was opened with carried the lab's access code as ?code=…; the capture
    keeps it in Referer and the evidence URL. Seen in a live bundle: the code sat in adapter.json,
    manifest.json and README.md. The bundle keeps the page, never the query values."""
    cfg = dict(CFG, headers={"Content-Type": "application/json",
                             "Referer": "https://lab.example.test/rest?code=lab-SECRET-CODE-1234",
                             "Origin": "https://lab.example.test"})
    m = bundle.write_bundle(cfg, tmp_path / "d", app_name="gated", app_id="aapp_2",
                            evidence={"config": "/x/gated.json", "captured": "https://lab.example.test/rest?code=lab-SECRET-CODE-1234"},
                            vendor_runtime=False)
    out = tmp_path / "d"
    everything = "".join((out / f).read_text() for f in ("adapter.json", "manifest.json", "README.md", "secrets.template.env"))
    assert "lab-SECRET-CODE-1234" not in everything
    assert json.loads((out / "adapter.json").read_text())["headers"]["Referer"] == "https://lab.example.test/rest"
    assert m["evidence"]["captured"] == "https://lab.example.test/rest?code=***"      # shape kept, value gone
    assert m["evidence"]["config"] == "/x/gated.json"


def test_redaction_helpers_leave_clean_urls_alone():
    assert bundle.strip_query("https://h/rest") == "https://h/rest"
    assert bundle.strip_query("https://h/rest?code=x#frag") == "https://h/rest"
    assert bundle.redact_url("https://h/rest") == "https://h/rest"
    assert bundle.redact_url("https://h/a?k=v&flag") == "https://h/a?k=***&flag"
    assert bundle.redact_evidence({"n": 3, "u": "https://h/a?t=1", "s": "plain"}) == {"n": 3, "u": "https://h/a?t=***", "s": "plain"}


def test_a_plain_direct_adapter_points_the_console_bridge_at_the_target(tmp_path):
    """The bridge the Console hands out forwards one POST with one auth block; a static-header
    direct adapter needs nothing else, so the bridge is pointed straight at the target."""
    cfg = {"adapter": "direct_api", "endpoint": "https://lab.example.test/rest/api/chat", "method": "POST",
           "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
           "headers": {"Content-Type": "application/json", "Origin": "https://lab.example.test"},
           "auth": {"type": "static", "mode": "headers", "headers": {"Cookie": "env:ASCEND_SECRET_LAB_COOKIE"}}}
    m = bundle.write_bundle(cfg, tmp_path / "e", app_name="rest", vendor_runtime=False)
    out = tmp_path / "e"
    assert m["bridge"]["console_bridge"]["points_at"] == "direct"
    assert m["bridge"]["console_bridge"]["image"] == "straikerai/ascendai-bridge:latest"
    assert m["bridge"]["console_bridge"]["console_request_template"] == {"message": "{{PROMPT}}"}
    assert m["bridge"]["console_bridge"]["console_response_path"] == "reply"
    y = (out / "bridge" / "config.yaml").read_text()
    assert 'url: "https://lab.example.test/rest/api/chat"' in y
    assert "type: custom" in y and "Cookie:" in y and "ASCEND_SECRET_LAB_COOKIE" in y
    assert "env:" not in y.split("Cookie:")[1].splitlines()[0]        # a placeholder, never the ref syntax or a value
    assert "transport: pull" in y
    assert "straikerai/ascendai-bridge:latest" in (out / "bridge" / "docker-compose.yaml").read_text()


def test_everything_else_points_the_console_bridge_at_the_shim(tmp_path):
    m = bundle.write_bundle(CFG, tmp_path / "f", app_name="session", vendor_runtime=False)     # derived_multihop
    out = tmp_path / "f"
    assert m["bridge"]["console_bridge"]["points_at"] == "shim"
    assert m["bridge"]["console_bridge"]["console_request_template"] == {"prompt": "{{PROMPT}}"}
    assert m["bridge"]["console_bridge"]["console_response_path"] == "response"
    y = (out / "bridge" / "config.yaml").read_text()
    assert "http://shim:8787/chat" in y and "api_key_name: X-Shim-Key" in y
    c = (out / "bridge" / "docker-compose.yaml").read_text()
    assert "TARGET_APP_API_KEY_NAME: X-Shim-Key" in c and "shim/Dockerfile" in c and "depends_on: [shim]" in c
    assert m["bridge"]["cli_relay"]["protocol"].startswith("v2 lease")


def test_a_streaming_adapter_goes_through_the_shim(tmp_path):
    cfg = {"adapter": "sse_stream", "base_url": "https://lab.example.test", "chat_path": "/sse/api/chat",
           "stream": {"format": "sse"}, "headers": {"Cookie": "env:ASCEND_SECRET_LAB_COOKIE"}}
    assert bundle.console_bridge_plan(cfg)["target"] == "shim"
    ws = {"adapter": "websocket_direct", "ws_url": "wss://gw.example.test/demo"}
    assert bundle.console_bridge_plan(ws)["target"] == "shim"
