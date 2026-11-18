"""The agent must WIRE a Salesforce Embedded Messaging (SCRT2) widget from a capture on its own.

Regression for the derivation gap that made every `*.my.salesforce-scrt.com` chat widget fail with
"Missing required config: scrt_base, org_id, developer_name, widget_origin": the preset picked the
scrt2_direct adapter but compose() never filled the adapter's four fields, leaving them for the
operator. They are all present in a normal capture (the accessToken call body + the scrt host + the
Origin header), so the agent derives them itself. Synthetic capture — no customer data.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime.discovery import classify


def _pair(method, url, req_headers=None, req_body=None, resp_body=None, status=200):
    return {"request": {"method": method, "url": url,
                        "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
                        "body": req_body},
            "response": {"status": status,
                         "headers": [{"name": "content-type", "value": "application/json"}],
                         "body": resp_body}}


def _evidence():
    scrt = "https://acme.my.salesforce-scrt.com"
    origin = "https://www.acme.example"
    pairs = [
        # the accessToken (authorization) call — carries orgId + developerName
        _pair("POST", f"{scrt}/iamessage/v1/authorization/unauthenticated/accessToken",
              {"origin": origin, "content-type": "application/json"},
              '{"orgId":"00D000000000ABC","esDeveloperName":"Acme_AgentForce","capabilitiesVersion":"260"}',
              '{"accessToken":"x"}'),
        # create conversation
        _pair("POST", f"{scrt}/iamessage/v1/conversation", {"origin": origin}, '{"conversationId":"c1"}', '{"ok":true}'),
        # the message send — the chat exchange the classifier keys on
        _pair("POST", f"{scrt}/iamessage/v1/conversation/c1/message", {"origin": origin},
              '{"message":{"text":"hello"}}', '{"messages":[{"text":"hi there"}]}'),
    ]
    return classify.har_to_evidence({"log": {"entries": [
        {"request": {"method": p["request"]["method"], "url": p["request"]["url"],
                     "headers": p["request"]["headers"],
                     "postData": {"text": p["request"]["body"]} if p["request"]["body"] else None},
         "response": {"status": p["response"]["status"], "headers": p["response"]["headers"],
                      "content": {"text": p["response"]["body"], "mimeType": "application/json"}}}
        for p in pairs]}}, prompt_sent="hello")


def test_scrt2_widget_is_wired_from_the_capture():
    res = classify.classify_evidence(_evidence())
    cfg = res["config"]
    assert cfg["adapter"] == "scrt2_direct", cfg.get("adapter")
    assert cfg.get("scrt_base") == "https://acme.my.salesforce-scrt.com", cfg
    assert cfg.get("org_id") == "00D000000000ABC", cfg
    assert cfg.get("developer_name") == "Acme_AgentForce", cfg
    assert cfg.get("widget_origin") == "https://www.acme.example", cfg
    assert cfg.get("capabilities_ver") == "260", cfg
    # the whole point: nothing the operator has to hand-fill
    missing = [k for k in ("scrt_base", "org_id", "developer_name", "widget_origin") if not cfg.get(k)]
    assert not missing, f"still missing {missing}"


def _scrt2_with_recorded_network():
    """An SCRT2 adapter whose four network calls are recorded instead of sent."""
    from runtime.adapters.scrt2_direct import SCRT2DirectAdapter
    calls = {"sent": [], "reads": []}
    ad = SCRT2DirectAdapter()
    ad._get_token = lambda *a, **k: "jwt"
    ad._create_conversation = lambda *a, **k: "conv1"

    def _send(scrt_base, jwt, conv_id, text, origin, *a, **k):
        calls["sent"].append(text)
    ad._send_message = _send

    def _read(scrt_base, jwt, org_id, origin, timeout=45, skip_count=0, *a, **k):
        calls["reads"].append(skip_count)
        return "the model's real answer to the probe"
    ad._read_sse_response = _read
    return ad, calls


_SCRT2_BASE = {
    "adapter": "scrt2_direct",
    "scrt_base": "https://acme.my.salesforce-scrt.com",
    "org_id": "00D000000000ABC",
    "developer_name": "Acme_AgentForce",
    "widget_origin": "https://www.acme.example",
}


def test_scrt2_honours_a_warmup_written_under_the_legacy_key():
    """SCRT2 bots answer the first turn of every conversation with a consent banner. The adapter
    clears it by sending a throwaway opener first — but only if it can read the warm-up text.

    The `--warmup` flag and the create-then-send derivation write the key `warmup`; this adapter
    used to read only `warmup_message`, so a config carrying `warmup` skipped the warm-up and every
    probe was scored against the consent banner. It now reads
    through `warmup_text()`, which accepts every key a writer has used.

    Mutation anchor: revert the adapter to `config.get("warmup_message", "")` and this goes red.
    """
    import asyncio
    ad, calls = _scrt2_with_recorded_network()
    cfg = dict(_SCRT2_BASE, warmup="ok i acknowledge. can you let me know what you can help me with?")
    res = asyncio.run(ad.send_prompt("what is 2+2?", cfg))

    assert res["success"], res
    # the opener went out BEFORE the probe
    assert len(calls["sent"]) == 2, calls["sent"]
    assert calls["sent"][0].startswith("ok i acknowledge"), calls["sent"]
    assert calls["sent"][1] == "what is 2+2?", calls["sent"]
    # the probe's answer was read past the replayed greeting (skip_count=1): the warm-up path
    assert calls["reads"] == [0, 1], f"warm-up path not taken; reads={calls['reads']}"
    assert res["response"] == "the model's real answer to the probe", res


def test_scrt2_without_any_warmup_sends_the_probe_alone():
    """The negative case, so the test above cannot pass by always warming up."""
    import asyncio
    ad, calls = _scrt2_with_recorded_network()
    res = asyncio.run(ad.send_prompt("what is 2+2?", dict(_SCRT2_BASE)))
    assert res["success"], res
    assert calls["sent"] == ["what is 2+2?"], calls["sent"]
    assert calls["reads"] == [0], calls["reads"]


if __name__ == "__main__":
    test_scrt2_widget_is_wired_from_the_capture()
    test_scrt2_honours_a_warmup_written_under_the_legacy_key()
    test_scrt2_without_any_warmup_sends_the_probe_alone()
    print("ok — scrt2 wired from the capture; warm-up honoured under either key")
