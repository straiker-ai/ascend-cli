#!/usr/bin/env bash
# Build a single self-contained `ascend` executable — no Python needed on the target
# machine. This is the lowest-friction way to hand the tool to a customer.
#
#   ./scripts/build_binary.sh          -> dist/ascend
#   ./dist/ascend doctor
#
# Notes
#  * Build on the platform you are shipping to (macOS arm64 binary != Linux x64).
#  * `discover --url` needs a browser at RUNTIME; the binary does not bundle Chromium.
#    Everything else (relay, assessments, adapters, export, CI) is fully self-contained.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

command -v pyinstaller >/dev/null 2>&1 || {
  echo "pyinstaller not found. Install it with:  python3 -m pip install pyinstaller" >&2
  exit 1
}

rm -rf build dist/ascend

# Ship ONLY the example-*.json templates. Never bundle customer configs — they
# carry real endpoints, tokens and session material (configs/*.json is gitignored
# for the same reason). Whitelist explicitly; do not blanket-bundle configs/.
cfg_data=()
for f in configs/example-*.json; do cfg_data+=(--add-data "$f:configs"); done

pyinstaller \
  --onefile \
  --name ascend \
  --paths . --paths runtime --paths control --paths reporting --paths transport \
  --hidden-import requests --hidden-import websockets \
  --collect-submodules runtime \
  --collect-submodules control \
  --collect-submodules reporting \
  --collect-submodules transport \
  "${cfg_data[@]}" \
  --add-data "docs:docs" \
  --add-data "skills:skills" \

  shells/cli/ascend.py

echo
echo "built: dist/ascend  ($(du -h dist/ascend 2>/dev/null | cut -f1))"
echo "smoke test:"
./dist/ascend --version
./dist/ascend adapter list >/dev/null && echo "  adapter list OK"

# reporting must be bundled (this is the check that catches the enterprise/ drift).
printf '{"assessment_id":"a","status":"completed","results":[]}' > "${TMPDIR:-/tmp}/_ascend_smoke.json"
./dist/ascend export --file "${TMPDIR:-/tmp}/_ascend_smoke.json" --format sarif >/dev/null \
  && echo "  export (reporting) OK" || { echo "  export FAILED — reporting not bundled" >&2; exit 1; }

# Only the whitelisted example templates are bundled (the loop above is the
# guarantee); a run from a clean cwd sees no customer configs.
echo "  bundled configs: $(cd "${TMPDIR:-/tmp}" && "$HERE/dist/ascend" adapter configs 2>/dev/null | grep -c 'example-') example template(s)"
echo
echo "ship it:  scp dist/ascend <host>:  &&  ./ascend doctor"
