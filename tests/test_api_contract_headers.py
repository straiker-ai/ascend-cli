"""A direct (api-type) app carries the headers the target may check, not the ones a browser adds
for itself. The platform rejected a create with the full captured set; the credential must stay."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "", "shells/cli"):
    sys.path.insert(0, str(ROOT / p))
import ascend  # noqa: E402

CAPTURED = {
    "Accept": "*/*", "Accept-Language": "en-US", "Content-Type": "application/json",
    "Origin": "https://lab.example.test", "Referer": "https://lab.example.test/rest",
    "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Macintosh)", "Sec-Ch-Ua": '"Chromium";v="154"',
    "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"macOS"', "x-lab-code": "code-9f13",
}


def test_browser_only_headers_are_dropped_and_the_rest_kept():
    out = ascend._api_contract({"url": "https://lab.example.test/rest/api/chat", "headers": CAPTURED,
                                "body": {"message": "{{PROMPT}}"}, "response_path": "reply"})
    names = {k.lower() for k in out["headers"]}
    assert not any(n.startswith("sec-") for n in names)
    assert "user-agent" not in names and "accept-language" not in names
    assert {"accept", "content-type", "origin", "referer", "x-lab-code"} <= names
    assert out["headers"]["x-lab-code"] == "code-9f13"


def test_a_static_credential_from_the_auth_block_still_lands(monkeypatch):
    monkeypatch.setenv("LAB_COOKIE_T", "lab_access=code-9f13")
    out = ascend._api_contract({"url": "https://lab.example.test/rest/api/chat", "headers": {"Content-Type": "application/json"},
                                "auth": {"type": "static", "mode": "headers", "headers": {"Cookie": "env:LAB_COOKIE_T"}},
                                "body": {"message": "{{PROMPT}}"}})
    assert out["headers"]["Cookie"] == "lab_access=code-9f13"
