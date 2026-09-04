# internal/ — NOT SHIPPED

Everything in this directory except this README is **gitignored on purpose**.

This repo is intended to become public for customers. **Making a repo public exposes its
entire git history**, so anything committed here — even if deleted later — would remain
permanently visible. Keep internal material local and share it out of band (Drive/Slack).

Contents (local only):

| File | What |
|---|---|
| `CONNECTIVITY.md` | Site-by-site results of live connectivity testing: which real bots we reached, the vendor platform behind each, and which adapter drives them. |
| `SE_RUNBOOK.md` | Field runbook for SEs: engagement flow, gotchas, what to do when a widget won't capture. |
| `ENGINEERING_HANDOFF.md` | Architecture decisions, known gaps, and the prioritized build queue for engineering. |

If you need something from here in the public repo, genericize it first: platform/vendor
names (Salesforce, Slack, Intercom) are fine as **integration types**; customer names,
engagement details, tokens, and per-customer endpoints are not.

Drop internal engineering material here — backend architecture decks, deep-dive slides,
exported diagrams. Everything in this directory except this README is gitignored, so it stays
local to your machine and can never reach the public repo or its history.
