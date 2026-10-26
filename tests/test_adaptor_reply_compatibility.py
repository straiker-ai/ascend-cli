"""Template extraction examples are not complete current-v1 raw-reply contracts."""
import json
import shutil
import subprocess
from copy import deepcopy

import pytest

from runtime.discovery import codegen_js as G
from test_adaptor_cli import APP, REPO, Recorder, cli, run


@pytest.mark.parametrize("template,path", [
    ("{{RESPONSE}}", ""),
    ({"text": "{{RESPONSE}}"}, "text"),
    ({"message": {"selected": "{{RESPONSE}}"}}, "message.selected"),
    ({"text": {"content": "{{RESPONSE}}"}}, "text.content"),
    ({"text": [{"content": "{{RESPONSE}}"}]}, "text.0.content"),
    ({"choices": [{"message": {"content": "{{RESPONSE}}"}}]}, "choices.0.message.content"),
    ([{"content": "{{RESPONSE}}"}], "0.content"),
])
def test_reply_shape_has_additive_v1_guidance_without_changing_template(template, path):
    before = deepcopy(template)
    shape = cli._adaptor_mod().reply_shape(json.dumps(template))
    assert shape["path"] == path and template == before
    assert set(shape) == {"path", "statement", "statement_scope", "v1_compatibility"}
    assert shape["statement_scope"] == "response_template_only"
    note = shape["v1_compatibility"]
    assert type(note) is str and len(note.encode("utf-8")) <= 1200
    for phrase in ("Current v1", "Whole-body strings", "body.text", "object/list", "conflict",
                   "selected assistant", "response_template", "completion", "conversation",
                   "Never use object serialization", "proof"):
        assert phrase in note
    assert "verified" not in shape and "source" not in shape


@pytest.mark.parametrize("json_mode", [False, True])
def test_actual_shape_command_exposes_template_only_scope_and_v1_guidance(monkeypatch, capsys, json_mode):
    record = Recorder(app={**APP, "response_template": '{"message":{"selected":"{{RESPONSE}}"}}'})
    before = deepcopy(record.app)
    run(monkeypatch, record, "adaptor", "shape", "--app", "aapp_1", json_mode=json_mode)
    output = capsys.readouterr().out
    if json_mode:
        data = json.loads(output)["data"]
        assert data["response_template"] == before["response_template"]
        assert data["reply_shape"] == cli._adaptor_mod().reply_shape(before["response_template"])
        assert data["reply_shape"]["statement_scope"] == "response_template_only"
        assert "Current v1" in data["reply_shape"]["v1_compatibility"]
    else:
        assert "RESPONSE_TEMPLATE-ONLY return example" in output
        assert "statement_scope: response_template_only" in output
        assert "v1_compatibility: Current v1" in output
        assert "body: { message: { selected: text } }" in output
    assert record.app == before
    assert not record.gated and not record.tested and not record.patched and not record.verified


def _composed_source(protocol):
    # The unchanged CLI decoder is a fixture oracle, not new generated production
    # behavior. A separately authored wrapper preserves its failures and selects
    # the same string for raw reading and the configured nested extraction.
    cfg = {"endpoint": "https://fixture.example.test/reply", "headers": {}}
    if protocol == "json":
        cfg.update(adapter="direct_api", body={"input": "{{PROMPT}}"}, response_path="assistant.text")
        selected = "result.body.assistant.text"
    else:
        cfg.update(adapter="sse_stream", base_url=cfg["endpoint"],
                   request_template={"input": "{{PROMPT}}"},
                   stream={"format": "ndjson", "text_path": "fragment", "token_types": ["assistant"],
                           "done_when": {"path": "finished", "equals": True}})
        selected = "result.body.response"
    return G.plan(cfg)["source"] + '''
var decodeDeclaredReply = sendTurn;
sendTurn = function(turn, host) {
  var result = decodeDeclaredReply(turn, host);
  if (result.status_code !== 200) return result;
  var selected = %s;
  if (typeof selected !== "string" || !selected.trim())
    return {status_code:502,body:{error:"no selected assistant reply"}};
  return {status_code:200,body:{text:selected,message:{selected:selected},
    context:{turnToken:turn.payload.turnToken}}};
};
''' % selected


@pytest.mark.parametrize("protocol", ["json", "ndjson"])
@pytest.mark.parametrize("case", ["complete", "http_failure", "malformed", "no_selected_reply"])
def test_composed_reply_keeps_scalar_nested_text_context_and_protocol_failures(protocol, case):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node executes the synthetic adapter, not a platform engine")
    answer = "A synthetic selected assistant answer."
    if protocol == "json":
        wire = json.dumps({"assistant": {"text": answer}})
        if case == "no_selected_reply": wire = '{"metadata":{"text":"not an assistant reply"}}'
    else:
        wire = '\n'.join([json.dumps({"type": "user", "fragment": "not selected"}),
            json.dumps({"type": "assistant", "fragment": answer}),
            json.dumps({"finished": True})]) + '\n'
        if case == "no_selected_reply": wire = '{"type":"user","fragment":"not selected"}\n{"finished":true}\n'
    if case == "malformed": wire += "invalid frame"
    scenario = {"source": _composed_source(protocol), "config": {"url": "https://fixture.example.test/reply"},
        "turn": {"payload": {"input": "Synthetic input.", "turnToken": "synthetic-context"}, "headers": {}},
        "scenario": {"http": [{"status": 503 if case == "http_failure" else 200, "body": wire}]}}
    completed = subprocess.run([node, str(REPO / "tests" / "_adaptor_host.js")], input=json.dumps(scenario),
        text=True, capture_output=True, timeout=10, check=True)
    output = json.loads(completed.stdout)
    assert output["error"] is None
    result = output["reply"]
    assert len([call for call in output["calls"] if call["fn"] == "http.request"]) == 1
    if case == "complete":
        assert result["status_code"] == 200
        assert result["body"]["text"] == result["body"]["message"]["selected"] == answer
        assert result["body"]["context"] == {"turnToken": "synthetic-context"}
    else:
        assert result["status_code"] != 200 and "message" not in result["body"] and "text" not in result["body"]


def test_declared_stream_completion_is_not_replaced_by_compatibility_text():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node executes the synthetic adapter, not a platform engine")
    scenario = {"source": _composed_source("ndjson"), "config": {"url": "https://fixture.example.test/reply"},
        "turn": {"payload": {"input": "Synthetic input."}},
        "scenario": {"http": [{"body": '{"type":"assistant","fragment":"Incomplete synthetic reply."}\n'}]}}
    completed = subprocess.run([node, str(REPO / "tests" / "_adaptor_host.js")], input=json.dumps(scenario),
        text=True, capture_output=True, timeout=10, check=True)
    output = json.loads(completed.stdout)
    assert output["error"] is None and output["reply"]["status_code"] == 502
    assert "text" not in output["reply"]["body"] and "message" not in output["reply"]["body"]
