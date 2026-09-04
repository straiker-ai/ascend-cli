"""
test_no_internal_codenames.py — a customer never reads an internal codename.

This repo is public and its output is what a customer sees first. The launch screen's diagram
named the assessment engine "Iris", an internal service name; in the customer's world that is
**Ascend AI**, running in the Straiker cloud. The same word had spread into the generated adapter
scaffold, the recon help, six docs pages and the architecture diagram.

The check is deliberately blunt: the words must not appear in user-visible output or in any
shipped file. A new internal service name added to this list is protected the same way.
"""
import io
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

#: Internal service / project names. The customer-facing word for each is in the comment.
INTERNAL = {
    "iris": "Ascend AI (the assessment engine in the Straiker cloud)",
    "argus": "Defend AI (the runtime detection service)",
    "probe_shadow": "the lease service",
    "pallas": "an internal project name",
}

#: Files that may legitimately carry one: none. Historical changelog entries were rewritten too,
#: because a customer reads the changelog.
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "captures", "configs", "node_modules", "demo"}
TEXT_SUFFIXES = {".py", ".md", ".mdx", ".html", ".txt", ".toml", ".yml", ".yaml", ".tape", ".json"}


def shipped_files():
    for p in REPO.rglob("*"):
        if not p.is_file() or p.suffix not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(REPO).parts):
            continue
        if p.name == "test_no_internal_codenames.py":
            continue
        yield p


@pytest.mark.parametrize("word", sorted(INTERNAL))
def test_no_shipped_file_names_an_internal_service(word):
    # `probe_shadow` also ships as "Probe Shadow" and "probe-shadow"; the underscore-only pattern
    # let the spaced form through in transport/openapi.yaml, which a customer downloads.
    loose = re.escape(word).replace("_", "[ _-]?")
    pat = re.compile(rf"\b{loose}\b", re.I)
    hits = []
    for p in shipped_files():
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                hits.append(f"{p.relative_to(REPO)}:{i}: {line.strip()[:100]}")
    assert not hits, (f"{word!r} is an internal name; a customer should read "
                      f"{INTERNAL[word]!r} instead:\n  " + "\n  ".join(hits[:12]))


class TestTheLaunchScreen:
    def test_the_diagram_names_the_product_not_the_service(self):
        buf = io.StringIO()
        ascend._print_flow(buf)
        art = buf.getvalue()
        assert "Ascend AI" in art and "iris" not in art.lower()

    def test_it_is_the_three_column_diagram(self):
        buf = io.StringIO()
        ascend._print_flow(buf)
        head = buf.getvalue().splitlines()[0]
        assert "straiker cloud" in head and "your machine" in head and "your target" in head, head

    def test_the_diagram_is_the_first_block_of_a_bare_ascend(self):
        """A bare `ascend` on a terminal opens with the wordmark and then the diagram — nothing
        else may come between them, because that picture is the product's first explanation."""
        src = ascend.__loader__.get_source("ascend") if hasattr(ascend, "__loader__") else ""
        body = src.split("def _launch_screen(")[1].split("\ndef ")[0]
        i_banner, i_flow = body.index("_brand_banner()"), body.index("_print_flow(")
        assert i_banner < i_flow, "the wordmark comes first"
        between = body[i_banner:i_flow]
        assert between.count("print(") <= 4, f"something new sits between the wordmark and the diagram:\n{between}"

    def test_help_output_is_clean(self):
        r = subprocess.run([sys.executable, str(REPO / "shells" / "cli" / "ascend.py"), "--help"],
                           capture_output=True, text=True)
        blob = (r.stdout + r.stderr).lower()
        for word in INTERNAL:
            assert word not in blob, f"`ascend --help` says {word!r}"
