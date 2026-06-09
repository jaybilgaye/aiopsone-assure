"""Load security findings from various sources into a normalised list.

Supported inputs (auto-detected):
  - Prowler CSV (standard `-M csv`)         columns CHECK_ID / STATUS / ...
  - Prowler compliance CSV                  columns CHECKID / REQUIREMENTS_ID / ...
  - Prowler OCSF JSON (`-M json-ocsf`)      best-effort
  - A simple normalised JSON list           [{"check_id","status",...}, ...]

We deliberately map check -> control ourselves (see mapping.py) so we never
depend on the framework being installed inside the user's Prowler.
"""
import csv
import json
import io


class IngestError(ValueError):
    pass


class CheckResult:
    __slots__ = ("check_id", "status", "detail", "resource", "account", "region", "date")

    def __init__(self, check_id, status, detail="", resource="", account="", region="", date=""):
        self.check_id = check_id
        self.status = (status or "").strip().upper()
        self.detail = detail or ""
        self.resource = resource or ""
        self.account = account or ""
        self.region = region or ""
        self.date = date or ""


# Status normalisation: Prowler emits PASS/FAIL/MANUAL/MUTED and OCSF Pass/Fail.
_PASS = {"PASS", "PASSED"}
_FAIL = {"FAIL", "FAILED"}
_MUTE = {"MUTED", "MUTE", "SUPPRESSED"}


def _norm_key(k):
    return (k or "").strip().upper().replace("_", "")


def _pick(row_norm, *cands):
    for c in cands:
        v = row_norm.get(_norm_key(c))
        if v not in (None, ""):
            return v
    return ""


def _from_csv_text(text):
    # Sniff delimiter: Prowler uses ';'. Fall back to ','.
    first = text.splitlines()[0] if text.strip() else ""
    delim = ";" if first.count(";") >= first.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    if not reader.fieldnames:
        raise IngestError("CSV has no header row")

    results, ctx = [], {"account": "", "region": "", "date": ""}
    seen_any_checkcol = False
    for raw in reader:
        row = {_norm_key(k): v for k, v in raw.items() if k is not None}
        check = _pick(row, "CHECKID", "CHECK_ID")
        if check:
            seen_any_checkcol = True
        status = _pick(row, "STATUS", "STATUS_CODE")
        muted = _pick(row, "MUTED").strip().lower() in ("true", "1", "yes")
        ctx["account"] = ctx["account"] or _pick(row, "ACCOUNTID", "ACCOUNT_UID", "ACCOUNT_ID")
        ctx["region"] = ctx["region"] or _pick(row, "REGION")
        ctx["date"] = ctx["date"] or _pick(row, "ASSESSMENTDATE", "ASSESSMENT_START_TIME", "TIMESTAMP")
        if not check or muted or status.strip().upper() in _MUTE:
            continue
        results.append(CheckResult(
            check_id=check,
            status=status,
            detail=_pick(row, "STATUSEXTENDED", "STATUS_EXTENDED", "STATUS_DETAIL"),
            resource=_pick(row, "RESOURCEID", "RESOURCE_UID", "RESOURCENAME", "RESOURCE_NAME"),
            account=_pick(row, "ACCOUNTID", "ACCOUNT_UID", "ACCOUNT_ID"),
            region=_pick(row, "REGION"),
            date=_pick(row, "ASSESSMENTDATE", "ASSESSMENT_START_TIME", "TIMESTAMP"),
        ))
    if not seen_any_checkcol:
        raise IngestError("no CHECK_ID / CHECKID column found — is this a Prowler findings CSV?")
    return results, ctx


def _from_json_obj(data):
    # Accept a bare list, or {"findings": [...]} / OCSF-ish wrappers.
    if isinstance(data, dict):
        for key in ("findings", "results", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise IngestError("JSON findings must be a list (or an object containing one)")

    results, ctx = [], {"account": "", "region": "", "date": ""}
    for item in data:
        if not isinstance(item, dict):
            continue
        # OCSF (Prowler json-ocsf): status_code + nested metadata/resources/cloud.
        if "status_code" in item or "finding_info" in item:
            check = (
                (item.get("finding_info") or {}).get("uid")
                or ((item.get("metadata") or {}).get("event_code"))
                or item.get("check_id")
            )
            status = item.get("status_code") or item.get("status")
            res = ""
            r = item.get("resources") or []
            if r and isinstance(r, list) and isinstance(r[0], dict):
                res = r[0].get("uid") or r[0].get("name") or ""
            cloud = item.get("cloud") or {}
            acct = ((cloud.get("account") or {}).get("uid")) or ""
            region = cloud.get("region") or ""
            detail = (item.get("status_detail") or item.get("message") or "")
        else:
            check = item.get("check_id") or item.get("check") or item.get("CHECKID")
            status = item.get("status") or item.get("STATUS")
            res = item.get("resource") or item.get("resource_id") or ""
            acct = item.get("account") or item.get("account_id") or ""
            region = item.get("region") or ""
            detail = item.get("detail") or item.get("status_extended") or ""
        if not check:
            continue
        ctx["account"] = ctx["account"] or acct
        ctx["region"] = ctx["region"] or region
        results.append(CheckResult(check, status, detail, res, acct, region))
    return results, ctx


def load(path):
    """Load findings from a file path (.json or .csv), auto-detecting the format."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        raise IngestError(f"cannot read findings file '{path}': {e}") from e
    if not text.strip():
        return [], {"account": "", "region": "", "date": ""}

    stripped = text.lstrip()
    is_json = path.lower().endswith(".json") or stripped[:1] in ("[", "{")
    if is_json:
        try:
            return _from_json_obj(json.loads(text))
        except json.JSONDecodeError as e:
            if path.lower().endswith(".json"):
                raise IngestError(f"{path} is not valid JSON: {e}") from e
            # mislabelled — fall through to CSV
    return _from_csv_text(text)


def normalise_status(s):
    s = (s or "").strip().upper()
    if s in _PASS:
        return "PASS"
    if s in _FAIL:
        return "FAIL"
    return s or "INFO"
