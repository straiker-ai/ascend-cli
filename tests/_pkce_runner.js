// Loads an adaptor (or template) in a FRESH V8 context that has none of Node's own globals -- no
// Buffer, TextEncoder, crypto or atob, exactly like the engine isolate -- and prints
// pkceChallenge(argv[3]). Proves the PKCE SHA-256 + base64url helper in the login scaffold is pure
// JavaScript and correct. Used by tests/test_pkce_js.py against the RFC 7636 appendix-B vector.
"use strict";
const vm = require("vm");
const fs = require("fs");

const src = fs.readFileSync(process.argv[2], "utf8");
const sandbox = {};
vm.createContext(sandbox);
// What a Node script could reach but the isolate cannot: if any are present in this bare context,
// the helper might be leaning on them, so the test records and rejects that.
const leaked = ["Buffer", "TextEncoder", "crypto", "atob", "btoa", "process", "require"].filter(
  (g) => typeof sandbox[g] !== "undefined");
vm.runInContext(src, sandbox, { filename: "adaptor.js" });
if (typeof sandbox.pkceChallenge !== "function") {
  process.stderr.write("no pkceChallenge in the source");
  process.exit(2);
}
process.stdout.write(JSON.stringify({ challenge: sandbox.pkceChallenge(process.argv[3]), leaked }));
