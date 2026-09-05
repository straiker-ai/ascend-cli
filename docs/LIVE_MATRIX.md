# Live adapter matrix — shapes passing over time

Appended by `scripts/live_matrix_record.py` after every merge to main. Read the last column
first: it should be empty, and the count must never go down. A drop is a regression caught in an
hour instead of a round.

The number is a health number **only when every shape has a capture case**. On 2026-09-05 the
matrix knew how to capture 11 of the forge's 24 shapes; the other 13 scored as "no evidence could
be captured" and the run read 11/24 while every covered shape passed. Coverage was closed the same
day. Rows before that are marked.

| date | main | stage | passing | failing shapes | note |
|---|---|---|---|---|---|
| 2026-09-05 | `95f03c7` | derive | 11/24 | `ndjson` `lines` `graphql` `gateway` `blocks` `preamble` `envelope` `latin1` `soap` `grpc-web` `form` `rotate` `widget` | **coverage gap** — all 11 covered shapes passed; the 13 had no capture case |
| 2026-09-05 | `95f03c7`+matrix | derive | 17/24 | `ws` `graphql` `blocks` `envelope` `form` `rotate` `widget` | first full coverage; `ws` flaky (passed alone), `blocks`/`envelope` were stale forge expectations, four real gaps |
| 2026-09-05 | `95f03c7`+fixes | derive | 21/24 | `session` `envelope` `rotate` | `session` = candidate-order regression from this branch (fixed); `envelope` = stale expectation (corrected); `rotate` = known gap |
| 2026-09-05 | `feat/matrix-covers-every-shape` | derive | **23/24** | `rotate` | `rotate` = known gap (a rotating conversation id is invisible to one probe); sweep now covers every candidate path |
