"""
control/console.py — the Console's application uuid, joined by name, fully offline.

The engine's adaptor routes take the Console's uuid and 404 on the platform's `aapp_` id, and no
v3 field carries the uuid. The join is the Console's own `listApplications` remote function,
answered to a plain GET with the PAT-exchanged JWT as the `auth-id-token` cookie, in devalue's
flattened form. Pinned here: the devalue port, the request (URL, cookie, no body), the name match
and its url tie-break, the API-base to Console-base mapping, and the client wrapper's fallback.
"""
import importlib
import json

import pytest

from conftest import FakeResponse, install_fake_requests

console = importlib.import_module("console")
api = importlib.import_module("api")

UUID_A = "01a1220c-0d0f-722a-a94b-59bb8a3c6276"
UUID_B = "01a121e9-b759-741a-9b8c-865730c33ee3"


def flat_listing(rows):
    """devalue.stringify of `{_: [row, ...], q: 1}` — the shape the Console really answers."""
    arr = [{"_": 1, "q": 2}, [], 1]
    for row in rows:
        obj = {}
        for k, v in row.items():
            obj[k] = len(arr)
            arr.append(v)
        arr[1].append(len(arr))
        arr.append(obj)
    return json.dumps(arr)


ROWS = [{"irisId": UUID_A, "name": "Support Bot", "url": "https://bot.example.com/api/chat", "isSample": False},
        {"irisId": UUID_B, "name": "Support Bot", "url": "https://other.example.com/chat", "isSample": False},
        {"irisId": "01a121ed-6165-74ba-b322-97c4c6e84c06", "name": "lab target", "url": None, "isSample": True}]


class TestDevalue:
    def test_the_flattened_listing_is_hydrated(self):
        value = console.unflatten(flat_listing(ROWS))
        assert value["_"][0] == ROWS[0] and value["_"][2]["url"] is None
        assert value["q"] == 1

    def test_sentinels_and_scalars(self):
        assert console.unflatten("[1]") == 1
        assert console.unflatten(json.dumps([{"a": -1, "b": -2, "c": 1}, "x"])) == {"a": None, "b": None, "c": "x"}
        assert console.unflatten('{"not": "flat"}') == {"not": "flat"}

    def test_a_query_payload_is_the_flat_form_base64url(self):
        assert console.devalue_payload(None) == ""
        raw = console.devalue_payload({"applicationId": "u", "limit": 10})
        import base64
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
        assert json.loads(decoded) == [{"applicationId": 1, "limit": 2}, "u", 10]


class TestMatching:
    def test_an_exact_name_wins_ignoring_case_and_spacing(self):
        rows = [ROWS[2]]
        assert console.match_application(rows, "  LAB   target ")["irisId"] == ROWS[2]["irisId"]

    def test_a_partial_name_is_not_a_match(self):
        assert console.match_application(ROWS, "Support") is None

    def test_a_duplicate_name_is_settled_by_url(self):
        assert console.match_application(ROWS, "Support Bot", "https://other.example.com/chat")["irisId"] == UUID_B

    def test_trailing_path_slash_is_not_assumed_equivalent(self):
        assert console.match_application(ROWS, "Support Bot", "https://other.example.com/chat/") is None

    @pytest.mark.parametrize("url", [
        "https://elsewhere.example/chat", "https://bot.example/Chat?key=Value",
        "https://bot.example/chat?key=value", "https://bot.example/chat?Key=Value",
        "https://bot.example/chat/?key=Value", "https://bot.example/chat?key=Value#fragment",
        "https://user:pass@bot.example/chat?key=Value", "not a URL",
        "https://bot.example:bad/chat?key=Value", "", "https://bot.exa\nmple/chat?key=Value",
    ])
    def test_sole_name_cannot_override_url_conflict_or_invalid_url(self, url):
        rows = [{"name": "Bot", "irisId": UUID_A, "url": "https://bot.example/chat?key=Value"}]
        assert console.match_application(rows, "Bot", url) is None

    def test_scheme_and_host_case_are_not_path_or_query_case(self):
        row = {"name": "Bot", "irisId": UUID_A, "url": "https://bot.example/Chat?Key=Value"}
        assert console.match_application([row], "bot", "HTTPS://BOT.EXAMPLE/Chat?Key=Value") == row

    def test_missing_row_url_cannot_satisfy_supplied_url(self):
        assert console.match_application([{"name": "Bot", "irisId": UUID_A}], "Bot", "https://bot.example/") is None

    def test_two_matching_rows_stay_ambiguous(self):
        row = {"name": "Bot", "irisId": UUID_A, "url": "https://bot.example/"}
        assert console.match_application([row, dict(row, irisId=UUID_B)], "Bot", row["url"]) is None

    def test_a_duplicate_name_without_a_url_stays_ambiguous(self):
        assert console.match_application(ROWS, "Support Bot") is None


class TestConsoleBase:
    @pytest.mark.parametrize("api_base,expected", [
        ("https://api.prod.straiker.ai/api/v3", "https://app.straiker.ai"),
        ("https://api.dev.straiker.ai/api/v3", "https://app.dev.straiker.ai"),
        ("https://api.staging.straiker.ai", "https://app.staging.straiker.ai"),
        ("http://localhost:8000", "https://app.straiker.ai"),
        ("", "https://app.straiker.ai"),
    ])
    def test_the_console_fronting_an_api_base(self, api_base, expected, monkeypatch):
        monkeypatch.delenv("STRAIKER_CONSOLE_BASE", raising=False)
        assert console.console_base_for(api_base) == expected

    def test_the_environment_override_wins(self, monkeypatch):
        monkeypatch.setenv("STRAIKER_CONSOLE_BASE", "https://console.example.test/")
        assert console.console_base_for("https://api.prod.straiker.ai/api/v3") == "https://console.example.test"


class TestTheCall:
    def _client(self, monkeypatch, listing=None, status=200, body=None):
        seen = []

        def handler(method, url, kwargs):
            if url.endswith("/auth/token"):
                return FakeResponse(200, {"access_token": "JWT-1"})
            seen.append((method, url, kwargs))
            if body is not None:
                return FakeResponse(status, body)
            return FakeResponse(status, {"type": "result", "data": flat_listing(listing or ROWS)})

        install_fake_requests(monkeypatch, handler)
        return api.AscendAPI(token="s6r_pat_test"), seen

    def test_a_plain_get_with_the_jwt_as_the_cookie(self, monkeypatch):
        monkeypatch.delenv("STRAIKER_CONSOLE_BASE", raising=False)
        monkeypatch.delenv("STRAIKER_CONSOLE_REMOTE", raising=False)
        c, seen = self._client(monkeypatch)
        assert c.console_app_uuid("lab target") == "01a121ed-6165-74ba-b322-97c4c6e84c06"
        (method, url, kw), = seen
        assert method == "GET"
        assert url == "https://app.straiker.ai/_app/remote/3s6sbx/listApplications?payload="
        assert kw["headers"]["Cookie"] == "auth-id-token=JWT-1"
        assert "json" not in kw and "data" not in kw

    def test_the_url_tie_break_reaches_the_wrapper(self, monkeypatch):
        c, _ = self._client(monkeypatch)
        assert c.console_app_uuid("Support Bot", url="https://bot.example.com/api/chat") == UUID_A
        assert c.console_app_uuid("Support Bot") is None

    def test_an_unreadable_listing_is_none_with_the_reason_kept(self, monkeypatch):
        c, _ = self._client(monkeypatch, status=403, body={"type": "error"})
        assert c.console_app_uuid("lab target") is None
        assert "403" in c.last_console_error

    def test_an_error_envelope_is_not_a_listing(self, monkeypatch):
        c, _ = self._client(monkeypatch, body={"type": "error", "error": "bad payload", "status": 500})
        assert c.console_app_uuid("lab target") is None
        assert "error" in c.last_console_error

    def test_attempts_wait_for_a_just_created_app(self, monkeypatch):
        """The Console lists a new app a few seconds after the API created it."""
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        calls = {"n": 0}

        def handler(method, url, kwargs):
            if url.endswith("/auth/token"):
                return FakeResponse(200, {"access_token": "JWT-1"})
            calls["n"] += 1
            rows = [] if calls["n"] < 3 else ROWS[2:]
            return FakeResponse(200, {"type": "result", "data": flat_listing(rows)})

        install_fake_requests(monkeypatch, handler)
        c = api.AscendAPI(token="s6r_pat_test")
        assert c.console_app_uuid("lab target", attempts=4) == ROWS[2]["irisId"]
        assert calls["n"] == 3
