"""Aggregate normalised findings into per-control compliance results.

We own the check -> control mapping (from the framework's `Checks` arrays), so
this works on raw Prowler output without the framework being installed in Prowler.

Control status rollup (worst-case):
    FAIL          any mapped check failed
    PASS          at least one check ran and none failed
    MANUAL        governance/process control (no automatable checks)
    NOT_ASSESSED  control has checks, but none were present in the findings
"""
from collections import OrderedDict

from .ingest import normalise_status

FAIL, PASS, MANUAL, NOT_ASSESSED = "FAIL", "PASS", "MANUAL", "NOT_ASSESSED"


class ControlResult:
    __slots__ = ("control", "status", "fails", "pass_count", "total")

    def __init__(self, control, status, fails, pass_count, total):
        self.control = control
        self.status = status
        self.fails = fails            # list of {detail, resource, check}
        self.pass_count = pass_count
        self.total = total


def aggregate(framework, results):
    """Return OrderedDict[control_id -> ControlResult], preserving framework order."""
    by_check = {}
    for r in results:
        by_check.setdefault(r.check_id, []).append(r)

    out = OrderedDict()
    for c in framework.controls:
        if c.is_manual:
            out[c.id] = ControlResult(c, MANUAL, [], 0, 0)
            continue
        rs = [r for chk in c.checks for r in by_check.get(chk, [])]
        if not rs:
            out[c.id] = ControlResult(c, NOT_ASSESSED, [], 0, 0)
            continue
        fails, pass_count = [], 0
        for r in rs:
            st = normalise_status(r.status)
            if st == FAIL:
                fails.append({"detail": r.detail, "resource": r.resource, "check": r.check_id})
            elif st == PASS:
                pass_count += 1
        status = FAIL if fails else (PASS if pass_count else MANUAL)
        out[c.id] = ControlResult(c, status, fails, pass_count, len(rs))
    return out


def summarise(control_results):
    """Counts + automated compliance score."""
    vals = list(control_results.values())
    fails = [r for r in vals if r.status == FAIL]
    passes = [r for r in vals if r.status == PASS]
    manual = [r for r in vals if r.status == MANUAL]
    not_assessed = [r for r in vals if r.status == NOT_ASSESSED]
    automated = len(fails) + len(passes)
    score = round(100 * len(passes) / automated) if automated else 0
    return {
        "total": len(vals),
        "fail": len(fails),
        "pass": len(passes),
        "manual": len(manual),
        "not_assessed": len(not_assessed),
        "automated": automated,
        "score": score,
        "fails": fails,
    }
