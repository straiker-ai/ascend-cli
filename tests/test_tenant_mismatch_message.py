"""
test_tenant_mismatch_message.py — the tenant lock must say WHAT differs, not repeat one name twice.

Seen live on 2026-09-03:

    error: this CLI is locked to tenant 'straiker.ai (admin)', but the supplied credential
           belongs to 'straiker.ai (admin)'.

The refusal was CORRECT — the credential was for the Discover tenant (straikerId 37), the lock
was pinned to the demo tenant — but the message was self-contradictory and told the operator
nothing, because the label is derived from the PAT's email domain and role, and two tenants
administered from the same domain get the same label. The check compares fingerprints; the
message printed labels. It now prints the fingerprint too, and says outright when the names
collide.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
import tenant as T  # noqa: E402


class TestTheMessageShowsWhatActuallyDiffers:
    def test_identical_labels_still_produce_a_distinguishable_message(self):
        e = str(T.TenantMismatch("straiker.ai (admin)", "straiker.ai (admin)",
                                 "3b37efd9122750d1" + "a" * 48, "1c7e2fa9d2a4a6b5" + "b" * 48))
        assert "3b37efd91227" in e and "1c7e2fa9d2a4" in e, (
            "both ids must appear; without them the message reads 'locked to X but belongs to X'")
        assert "names match" in e, "say outright that the collision is on the label, not the tenant"

    def test_distinct_labels_do_not_get_the_collision_line(self):
        e = str(T.TenantMismatch("acme.com (admin)", "other.io (admin)", "a" * 64, "b" * 64))
        assert "names match" not in e
        assert "acme.com" in e and "other.io" in e

    def test_the_two_argument_form_still_works(self):
        """Anything constructing the old shape must not break."""
        e = str(T.TenantMismatch("x", "y"))
        assert "locked to tenant 'x'" in e and "belongs to 'y'" in e

    def test_the_remedy_is_still_named(self):
        e = str(T.TenantMismatch("x", "x", "a" * 64, "b" * 64))
        assert "ascend tenant switch --confirm" in e and "ascend tenant show" in e


class TestCheckPassesTheFingerprintsThrough:
    def test_check_raises_with_both_fingerprints(self, tmp_path, monkeypatch):
        import base64, json
        monkeypatch.setattr(T, "TENANT_FILE", tmp_path / "tenant.json")
        b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        jwt = lambda sid: f"{b64({'alg':'none'})}.{b64({'iss':'https://idp','straikerId':sid,'email':'a@straiker.ai','role':'admin'})}."
        T.check(jwt("1"))                          # pins tenant 1
        try:
            T.check(jwt("37"))                     # same email domain -> same LABEL, different tenant
        except T.TenantMismatch as e:
            assert e.pinned_fp and e.incoming_fp and e.pinned_fp != e.incoming_fp
            assert "names match" in str(e), "this is exactly the live case: same label, different id"
        else:
            raise AssertionError("a different straikerId must be refused")
