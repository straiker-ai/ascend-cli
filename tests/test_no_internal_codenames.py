"""
test_no_internal_codenames.py — a customer never reads an internal codename.

This repo is public, and its output is the first thing a customer sees. Internal service and project
names must not appear in any shipped file or in user-visible output. The customer-facing names are
Ascend AI (the assessment engine in the Straiker cloud) and Defend AI (runtime detection).

The protected names are stored only as SHA-256 digests, so this test does not publish the words it
guards. To protect a new name, add its digest:

    python3 -c "import hashlib; print(hashlib.sha256(b'<name in lower case>').hexdigest())"
"""
import functools
import hashlib
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

#: sha256(internal name, lower case) -> what a customer should read instead. A two-word name is
#: hashed joined with "_", which also covers its spaced and hyphenated forms.
INTERNAL = {
    "47612b3175fece07f6c3e91992412c5b16ca88a9068cb72fecbcf653eb5ffcd7": "Ascend AI (the assessment engine in the Straiker cloud)",
    "444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97": "Defend AI (the runtime detection service)",
    "de7f47456ce3ec92a81ef99712bf9ac1559a70004017cd30274d3983e6a0987e": "the lease service",
    "0573e210e217cab724201408bd3283349f7721953ba343fa6dc319f580ae4f7e": "an internal project name",
    "e04ea923deab50151c0289ec0cb3bb763241b949f7cf308cf7f5022b4116661e": "the browser bridge client",
}

#: Files that may legitimately carry one: none. Historical changelog entries were rewritten too,
#: because a customer reads the changelog.
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "captures", "configs", "node_modules", "demo"}
TEXT_SUFFIXES = {".py", ".md", ".mdx", ".html", ".txt", ".toml", ".yml", ".yaml", ".tape", ".json"}
_WORD = re.compile(r"[a-z0-9]+")


@functools.lru_cache(maxsize=None)
def _digest(word):
    return hashlib.sha256(word.encode()).hexdigest()


def internal_names_in(text):
    """Digests of internal names in text: each word, and each pair of adjacent words joined by '_'
    (so 'a_b', 'a b' and 'a-b' all match a two-word name)."""
    words = _WORD.findall(text.lower())
    found = set()
    for i, w in enumerate(words):
        if _digest(w) in INTERNAL:
            found.add(_digest(w))
        if i + 1 < len(words) and _digest(w + "_" + words[i + 1]) in INTERNAL:
            found.add(_digest(w + "_" + words[i + 1]))
    return found


def shipped_files():
    for p in REPO.rglob("*"):
        if not p.is_file() or p.suffix not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(REPO).parts):
            continue
        if p.name == "test_no_internal_codenames.py":
            continue
        yield p


@functools.lru_cache(maxsize=1)
def _hits_by_name():
    hits = {d: [] for d in INTERNAL}
    for p in shipped_files():
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for d in internal_names_in(line):
                hits[d].append(f"{p.relative_to(REPO)}:{i}: {line.strip()[:100]}")
    return hits


@pytest.mark.parametrize("digest", sorted(INTERNAL))
def test_no_shipped_file_names_an_internal_service(digest):
    hits = _hits_by_name()[digest]
    assert not hits, (f"an internal name is in a shipped file; a customer should read "
                      f"{INTERNAL[digest]!r} instead:\n  " + "\n  ".join(hits[:12]))


class TestTheLaunchScreen:
    def test_the_diagram_names_the_product_not_the_service(self):
        buf = io.StringIO()
        ascend._print_flow(buf)
        art = buf.getvalue()
        assert "Ascend AI" in art and not internal_names_in(art)

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
        blob = r.stdout + r.stderr
        assert not internal_names_in(blob), "`ascend --help` names an internal service"
