// @ts-check
// THE LOGIN-CAPABLE ONBOARDING ADAPTOR. For a public target that authenticates with a handshake
// the Ascend engine performs itself - an OAuth2 token mint, a CSRF bootstrap, a multi-step login.
// It gets the Application created, shows you exactly what the target said, and gives you the two
// pieces a login needs that a thin passthrough cannot:
//
//   * a place to MINT the credential ONCE per conversation (host.state.getOrMint), so the isolate
//     being destroyed between turns does not re-login on every turn, and
//   * a pure-JS PKCE helper - the isolate has no crypto, TextEncoder, Buffer or atob, so a
//     code_challenge has to be computed with plain arithmetic. pkceChallenge(verifier) does that.
//
//     ascend adaptor spec --out host.d.ts                 # the host surface this is typed against
//     ascend adaptor gate | test | store | verify         # the loop (docs/CUSTOM_ADAPTOR.md)
//
// WHAT TO FINISH. mintCredential() below has the SHAPE of a login but not your target's specifics:
// the login URL, the fields it wants, where the token comes back. Fill those from what `ascend
// adaptor test` shows the target saying. Until you do, this still reaches the target and reports
// what it answered - a 401 or an HTML login page IS the spec you write the login to.
//
// CONFIGURATION, in the Application's request_template:
//   _adaptor_login_url     the token/login endpoint (leave it unset to reach the target
//                          unauthenticated while you read its 401)
//   _adaptor_timeout_ms    per-request deadline (default 30000)

/** @typedef {import("./host").Host} Host */
/** @typedef {import("./host").Turn} Turn */

// --------------------------------------------------------------------------- PKCE (RFC 7636)
// code_challenge = base64url(sha256(code_verifier)). Pure JavaScript: 32-bit integer arithmetic
// only, no host crypto call, no TextEncoder/Buffer/atob. Vetted against RFC 7636 appendix B in
// tests/test_pkce_js.py. Call pkceChallenge(verifier) from your login's authorize step.

/**
 * @param {number[]} bytes
 * @returns {number[]} the 32 SHA-256 digest bytes
 */
function _sha256Bytes(bytes) {
  var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  var msg = bytes.slice();
  var byteLen = bytes.length;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  var hi = (byteLen / 0x20000000) >>> 0;          // floor(byteLen * 8 / 2^32)
  var lo = (byteLen * 8) >>> 0;
  msg.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
  msg.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  var w = [];
  var i, t;
  for (i = 0; i < msg.length; i += 64) {
    for (t = 0; t < 16; t++) {
      w[t] = ((msg[i + t * 4] << 24) | (msg[i + t * 4 + 1] << 16) |
              (msg[i + t * 4 + 2] << 8) | (msg[i + t * 4 + 3])) >>> 0;
    }
    for (t = 16; t < 64; t++) {
      var x15 = w[t - 15], x2 = w[t - 2];
      var s0 = (rotr(x15, 7) ^ rotr(x15, 18) ^ (x15 >>> 3)) >>> 0;
      var s1 = (rotr(x2, 17) ^ rotr(x2, 19) ^ (x2 >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (t = 0; t < 64; t++) {
      var bigS1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      var ch = ((e & f) ^ ((~e) & g)) >>> 0;
      var temp1 = (h + bigS1 + ch + K[t] + w[t]) >>> 0;
      var bigS0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      var temp2 = (bigS0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  var out = [];
  for (i = 0; i < 8; i++) {
    out.push((H[i] >>> 24) & 0xff, (H[i] >>> 16) & 0xff, (H[i] >>> 8) & 0xff, H[i] & 0xff);
  }
  return out;
}

/**
 * UTF-8 encode a string to a byte array (no TextEncoder in the isolate).
 * @param {string} str
 * @returns {number[]}
 */
function _utf8Bytes(str) {
  var bytes = [];
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c < 0x80) {
      bytes.push(c);
    } else if (c < 0x800) {
      bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c < 0xd800 || c >= 0xe000) {
      bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      i++;
      var c2 = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      bytes.push(0xf0 | (c2 >> 18), 0x80 | ((c2 >> 12) & 0x3f),
                 0x80 | ((c2 >> 6) & 0x3f), 0x80 | (c2 & 0x3f));
    }
  }
  return bytes;
}

/**
 * base64url (RFC 4648 section 5), no padding - the encoding PKCE code_challenge uses.
 * @param {number[]} bytes
 * @returns {string}
 */
function _base64url(bytes) {
  var A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var out = "";
  var i;
  for (i = 0; i + 2 < bytes.length; i += 3) {
    var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += A[(n >> 18) & 63] + A[(n >> 12) & 63] + A[(n >> 6) & 63] + A[n & 63];
  }
  var rem = bytes.length - i;
  if (rem === 1) {
    var n1 = bytes[i] << 16;
    out += A[(n1 >> 18) & 63] + A[(n1 >> 12) & 63];
  } else if (rem === 2) {
    var n2 = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += A[(n2 >> 18) & 63] + A[(n2 >> 12) & 63] + A[(n2 >> 6) & 63];
  }
  return out;
}

/**
 * The PKCE code_challenge for a code_verifier: base64url(sha256(verifier)).
 * @param {string} verifier
 * @returns {string}
 */
function pkceChallenge(verifier) {
  return _base64url(_sha256Bytes(_utf8Bytes(verifier)));
}

// --------------------------------------------------------------------------- the login + the turn
var TOKEN_SLOT = "login_token";

/**
 * A short, safe preview of whatever the target sent back - the spec you write the login to.
 * @param {unknown} body
 * @returns {string}
 */
function preview(body) {
  var s = typeof body === "string" ? body : JSON.stringify(body);
  if (!s) return "";
  return s.length > 600 ? s.slice(0, 600) + "... [truncated]" : s;
}

/**
 * Mint (or reuse) the credential this target logs in for - once per conversation, not per turn.
 * Returns null when no login is configured yet, so the turn still reaches the target and you can
 * read the 401 it answers with. Finish the body/extraction from what that 401 shows you.
 * @param {Host} host
 * @param {Object} params
 * @returns {string|null}
 */
function mintCredential(host, params) {
  var loginUrl = params._adaptor_login_url || host.config.get("_adaptor_login_url");
  if (!loginUrl) return null;
  var timeoutMs = Number(params._adaptor_timeout_ms) || 30000;
  return host.state.getOrMint(TOKEN_SLOT, { ttlMs: 3300000, waitMs: 10000 }, function () {
    // A scripted OAuth2/PKCE login computes its challenge here, before the authorize step:
    //   var verifier = params._adaptor_pkce_verifier;
    //   var body = { grant_type: "client_credentials" };
    //   if (verifier) { body.code_challenge = pkceChallenge(verifier); body.code_challenge_method = "S256"; }
    var body = { grant_type: "client_credentials" };
    var res = host.http.request(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body,
      timeoutMs: timeoutMs,
    });
    if (res.status < 200 || res.status >= 300) return null;
    var parsed;
    try {
      parsed = JSON.parse(res.body);
    } catch (e) {
      return null;
    }
    return (parsed && (parsed.access_token || parsed.token)) || null;
  });
}

/**
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function sendTurn(turn, host) {
  var url = host.config.endpoint();
  var params = turn.params || {};
  var timeoutMs = Number(params._adaptor_timeout_ms) || 30000;

  var headers = { "Content-Type": "application/json" };
  for (var k in turn.headers || {}) headers[k] = turn.headers[k];

  var token = mintCredential(host, params);
  if (!headers["Authorization"] && !headers["authorization"]) {
    var cred = token || host.config.apiKey();
    if (cred) headers["Authorization"] = "Bearer " + cred;
  }

  var res;
  try {
    res = host.http.request(url, {
      method: "POST", headers: headers, body: turn.payload, timeoutMs: timeoutMs,
    });
  } catch (e) {
    host.log("error", "login-scaffold: target unreachable", { url: url });
    return {
      status_code: 502,
      body: {
        reached: false,
        note: "LOGIN SCAFFOLD: could not reach the target at all. Check the endpoint and that it " +
              "is reachable from the Ascend engine. This is the one thing the scaffold fails on.",
        error: String(e && e.message ? e.message : e),
      },
    };
  }

  var understood = res.status >= 200 && res.status < 300;
  host.log("info", "login-scaffold: target answered", { status: res.status, logged_in: !!token });
  return {
    status_code: 200,
    body: {
      reached: true,
      target_status: res.status,
      logged_in: !!token,
      note: understood
        ? "LOGIN SCAFFOLD: the target answered 2xx. If that needed the login, finish " +
          "mintCredential() and return the real reply text instead of this envelope."
        : "LOGIN SCAFFOLD: reached and answered " + res.status + ". Set _adaptor_login_url and " +
          "finish mintCredential() from what it said - the body below is your starting spec.",
      target_body: preview(res.body),
      content_type: (res.headers || {})["content-type"] || "",
    },
  };
}
