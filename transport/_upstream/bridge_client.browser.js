// Straiker Bridge - pull-mode reference client for a browser DevTools console.
//
// Paste this into the console of any page loaded in your private network (e.g. your own
// target app's page) - no install needed. Same protocol as bridge_client.py in this folder:
// long-poll /v2/lease for probes addressed to your app, call your own target application,
// submit the result via /v2/result, repeat.
//
// Edit API_KEY, and replace callTarget() below, before pasting. Stop the loop at
// any time from the same console with: stopStraikerBridge()

(async () => {
  // ==========================================================================================
  // REPLACE ME: this is the one function you need to write. Everything below this point is
  // fixed protocol plumbing - you shouldn't need to touch it.
  //
  // `body`/`headers` are the already-rendered probe content from Straiker; everything about
  // the request to YOUR app - path, method, extra headers/auth, how the probe content maps
  // onto your app's own request shape - is yours to define below. Must return
  // {statusCode, body}: the real HTTP status and body your target returned.
  //
  // The implementation below is illustrative, NOT a working default - it will call whatever
  // literal path you leave in place. Point it at your real target before running this.
  // ==========================================================================================
  async function callTarget(body, headers) {
    const res = await fetch("/api/chat", {           // <-- your target's path
      method: "POST",                                 // <-- your target's method
      credentials: "include",                          // reuses this tab's own session/cookies
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),                       // <-- reshape if your app expects something else
    });
    const responseBody = await res.json().catch(() => res.text());
    return { statusCode: res.status, body: responseBody };
  }
  // ==========================================================================================
  // END REPLACE ME
  // ==========================================================================================

  const BASE_URL = "https://ascendai-bridge.prod.straiker.ai"; // Straiker-provided host
  const API_KEY = "STRAIKER_BRIDGE_API_KEY"; // per-app thin-client token, provisioned by Straiker
  const CONSUMER = `browser-${Math.random().toString(36).slice(2, 10)}`;

  const LEASE_URL = `${BASE_URL}/v2/lease`;
  const RESULT_URL = `${BASE_URL}/v2/result`;
  const MAX_PROBES_PER_LEASE = 10;
  const WAIT_MS = 25000; // server-side long-poll hold; clamped server-side to [0, 55000]

  async function postJson(url, payload) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${API_KEY}` },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  const lease = () =>
    postJson(LEASE_URL, { consumer: CONSUMER, max: MAX_PROBES_PER_LEASE, wait_ms: WAIT_MS });

  const submitResult = (requestId, msgId, statusCode, body, headers = {}) =>
    postJson(RESULT_URL, {
      request_id: requestId,
      msg_id: msgId,
      payload: { status_code: statusCode, body, headers },
    });

  window.__straikerBridgeRunning = true;
  window.stopStraikerBridge = () => {
    window.__straikerBridgeRunning = false;
  };

  console.log(`[straiker-bridge] starting, consumer=${CONSUMER}`);
  let backoffMs = 1000;
  let printedReady = false;
  while (window.__straikerBridgeRunning) {
    let leased;
    try {
      leased = await lease();
      backoffMs = 1000;
    } catch (e) {
      if (e.status === 401 || e.status === 403) {
        // Non-retriable: a bad/expired token won't heal on retry.
        console.error(`[straiker-bridge] fatal: bridge rejected the API key (HTTP ${e.status}). Check API_KEY.`);
        break;
      }
      console.warn(`[straiker-bridge] lease failed: ${e}, retrying in ${backoffMs}ms`);
      await new Promise((r) => setTimeout(r, backoffMs));
      backoffMs = Math.min(backoffMs * 2, 30000);
      continue;
    }

    if (!printedReady) {
      // First successful /v2/lease call is the real "ready" signal - it confirms
      // BASE_URL/API_KEY are actually valid, not just that the loop started.
      console.log(`[straiker-bridge] ready - consumer=${CONSUMER}, watching for probes`);
      printedReady = true;
    }

    // An empty probes list is the normal outcome of a timed-out long-poll, not an error -
    // deliberately not logged every cycle, or the console would fill up with noise every
    // ~25s while idle.
    const probes = leased.probes || [];
    if (probes.length > 0) {
      console.log(`[straiker-bridge] leased ${probes.length} probe(s)`);
    }

    // Processed concurrently, not one at a time: the assessment engine dispatches up to
    // probe_dispatch_concurrency (20 by default, a pod-wide multi-tenancy fairness knob,
    // nothing to do with bridge specifically) probes at once.
    await Promise.all(probes.map(async (probe) => {
      const { request_id: requestId, msg_id: msgId, message } = probe;
      const { body, headers = {} } = message.payload;

      console.log(`[straiker-bridge] → ${requestId}: calling target`);
      let statusCode, responseBody;
      try {
        ({ statusCode, body: responseBody } = await callTarget(body, headers));
        console.log(`[straiker-bridge] ← ${requestId}: target responded HTTP ${statusCode}`);
      } catch (e) {
        // Still submit a result rather than dropping the probe - a synthesized failure
        // completes the assessment's accounting; a dropped probe is only reclaimed after
        // ~90s, slower and noisier for no benefit.
        statusCode = 500;
        responseBody = { error: String(e) };
        console.warn(`[straiker-bridge] ← ${requestId}: callTarget threw: ${e}`);
      }

      try {
        await submitResult(requestId, msgId, statusCode, responseBody);
        console.log(`[straiker-bridge] ✓ ${requestId}: result submitted`);
      } catch (e) {
        // Safe to leave unsubmitted: the server reclaims and redelivers this probe after
        // ~90s of inactivity.
        console.warn(`[straiker-bridge] ✗ ${requestId}: submitResult failed: ${e}`);
      }
    }));
  }
  console.log("[straiker-bridge] stopped");
})();
