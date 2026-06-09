"""Unit + edge-case tests for aiopsone-assure. Run: pytest -q (or python tests/test_assure.py)."""
import json
import os
import sys

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
FIX = os.path.join(HERE, "fixtures")

from assure.core import frameworks, ingest, mapping, narrate, report  # noqa: E402

CPS234 = frameworks.load("cps234")


def fx(name):
    return os.path.join(FIX, name)


# ---------------------------------------------------------------- frameworks --
def test_bundled_frameworks_load():
    for alias in ("cps234", "cps230"):
        fw = frameworks.load(alias)
        assert fw.controls and fw.check_index
    assert set(frameworks.available()) >= {"cps234", "cps230"}


def test_unknown_framework_errors():
    try:
        frameworks.load("nope")
        assert False, "should raise"
    except frameworks.FrameworkError:
        pass


def test_manual_controls_have_no_checks():
    manual = [c for c in CPS234.controls if c.is_manual]
    assert manual, "framework should have governance/manual controls"
    assert all(not c.checks for c in manual)


# -------------------------------------------------------------------- ingest --
def test_ingest_standard_prowler_csv():
    results, ctx = ingest.load(fx("prowler_standard.csv"))
    ids = [r.check_id for r in results]
    assert "iam_user_administrator_access_policy" in ids
    # muted row (cloudtrail_kms_encryption_enabled, MUTED=True) is dropped
    assert "cloudtrail_kms_encryption_enabled" not in ids
    assert ctx["account"] == "460589075034" and ctx["region"] == "ap-southeast-2"


def test_ingest_compliance_csv():
    results, ctx = ingest.load(fx("compliance.csv"))
    assert any(r.check_id == "accessanalyzer_enabled" for r in results)
    assert ctx["account"] == "123456789012"


def test_ingest_json_and_ocsf():
    for name in ("findings.json", "ocsf.json"):
        results, ctx = ingest.load(fx(name))
        assert any(r.check_id == "iam_user_administrator_access_policy" for r in results)


def test_ingest_empty_is_graceful():
    results, ctx = ingest.load(fx("empty.csv"))
    assert results == []


def test_ingest_malformed_raises():
    try:
        ingest.load(fx("malformed.csv"))
        assert False, "should raise IngestError"
    except ingest.IngestError:
        pass


def test_ingest_missing_file_raises():
    try:
        ingest.load(fx("does_not_exist.csv"))
        assert False
    except ingest.IngestError:
        pass


# ------------------------------------------------------------------- mapping --
def test_aggregate_worst_case_and_manual():
    results, _ = ingest.load(fx("prowler_standard.csv"))
    cr = mapping.aggregate(CPS234, results)
    # access-control has a failing check -> FAIL
    assert cr["cps234-21-access-control"].status == mapping.FAIL
    # mfa control: alice PASS + bob FAIL + root FAIL -> FAIL (worst case)
    assert cr["cps234-21-mfa"].status == mapping.FAIL
    # a governance control -> MANUAL
    assert cr["cps234-13-roles-responsibilities"].status == mapping.MANUAL
    # every control accounted for
    assert len(cr) == len(CPS234.controls)


def test_unknown_checks_are_ignored():
    results, _ = ingest.load(fx("prowler_standard.csv"))
    cr = mapping.aggregate(CPS234, results)
    # the unmapped check must not create a phantom control
    assert all(cid in {c.id for c in CPS234.controls} for cid in cr)


def test_not_assessed_when_no_findings():
    cr = mapping.aggregate(CPS234, [])
    autos = [c for c in CPS234.controls if not c.is_manual]
    assert all(cr[c.id].status == mapping.NOT_ASSESSED for c in autos)
    # manual controls stay MANUAL even with zero findings
    manual = [c for c in CPS234.controls if c.is_manual]
    assert all(cr[c.id].status == mapping.MANUAL for c in manual)


def test_all_pass_scores_100():
    # synthesise PASS-only results for every automatable check
    pass_results = [ingest.CheckResult(chk, "PASS") for chk in CPS234.check_index]
    cr = mapping.aggregate(CPS234, pass_results)
    s = mapping.summarise(cr)
    assert s["fail"] == 0 and s["score"] == 100


def test_summarise_counts_consistent():
    results, _ = ingest.load(fx("prowler_standard.csv"))
    s = mapping.summarise(mapping.aggregate(CPS234, results))
    assert s["total"] == len(CPS234.controls)
    assert s["fail"] + s["pass"] + s["manual"] + s["not_assessed"] == s["total"]
    assert 0 <= s["score"] <= 100


# ------------------------------------------------------------------- reports --
def test_markdown_report_builds():
    results, ctx = ingest.load(fx("prowler_standard.csv"))
    cr = mapping.aggregate(CPS234, results)
    md = report.build_markdown(CPS234, cr, ctx, narrate.narrate_template)
    assert "# APRA" in md and "Executive summary" in md
    assert "Remediation roadmap" in md  # there are fails
    assert "Not compliant" in md or "Manual" in md


def test_html_report_builds_and_escapes():
    results, ctx = ingest.load(fx("prowler_standard.csv"))
    cr = mapping.aggregate(CPS234, results)
    html_doc = report.build_html(CPS234, cr, ctx, narrate.narrate_template)
    assert html_doc.startswith("<!DOCTYPE html>")
    assert "automated" in html_doc and "Control-by-control" in html_doc
    # bold markdown converted, not leaked
    assert "**" not in html_doc.split("<style>")[0] + html_doc.split("</style>")[-1]


def test_inline_escaping_blocks_html_injection():
    bad = report._inline("<script>alert(1)</script> **bold**")
    assert "<script>" not in bad and "<strong>bold</strong>" in bad


def test_inline_preserves_iam_wildcards():
    # regression: literal *:* / s3:* must not be eaten by markdown-italic conversion
    out = report._inline("Remove *:* and s3:* policies")
    assert "*:*" in out and "s3:*" in out and "<em>" not in out


def test_empty_findings_report_no_roadmap():
    cr = mapping.aggregate(CPS234, [])
    md = report.build_markdown(CPS234, cr, {}, narrate.narrate_template)
    assert "Remediation roadmap" not in md  # nothing failed
    assert "not assessed" in md.lower()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
