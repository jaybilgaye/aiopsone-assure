"""Framework loading + alias resolution.

A "framework" is just data: the APRA mapping JSON (control -> paragraph + the
checks that evidence it). Bundled frameworks ship with the package; users can
also pass a path to their own framework pack JSON.
"""
import json
import os
from importlib import resources

# Friendly alias -> bundled data file.
ALIASES = {
    "cps234": "cps234.json",
    "cps-234": "cps234.json",
    "apra_cps_234_aws": "cps234.json",
    "cps230": "cps230.json",
    "cps-230": "cps230.json",
    "apra_cps_230_aws": "cps230.json",
}


class FrameworkError(ValueError):
    """Raised when a framework can't be resolved or is malformed."""


class Control:
    """One requirement of a framework, flattened for use."""

    __slots__ = (
        "id", "name", "description", "section", "paragraph", "assessment",
        "checks", "rationale", "impact", "remediation", "audit", "reference",
    )

    def __init__(self, req):
        attrs = (req.get("Attributes") or [{}])[0]
        self.id = req["Id"]
        self.name = req.get("Name") or req["Id"]
        self.description = req.get("Description", "")
        self.checks = list(req.get("Checks") or [])
        self.section = attrs.get("Section", "")
        self.paragraph = attrs.get("ItemId", "")
        self.assessment = (attrs.get("AssessmentStatus") or "").strip()
        self.rationale = attrs.get("RationaleStatement", "")
        self.impact = attrs.get("ImpactStatement", "")
        self.remediation = attrs.get("RemediationProcedure", "")
        self.audit = attrs.get("AuditProcedure", "")
        self.reference = attrs.get("References", "")

    @property
    def is_manual(self):
        # Manual if explicitly marked, or there is simply nothing to scan for it.
        return self.assessment.lower() == "manual" or not self.checks


class Framework:
    def __init__(self, data):
        if "Requirements" not in data:
            raise FrameworkError("framework JSON has no 'Requirements' array")
        self.id = data.get("Framework", "")
        self.name = data.get("Name", self.id or "Compliance framework")
        self.version = str(data.get("Version", ""))
        self.provider = data.get("Provider", "AWS")
        self.description = data.get("Description", "")
        self.controls = [Control(r) for r in data["Requirements"]]
        if not self.controls:
            raise FrameworkError("framework has zero requirements")
        # check_id -> [control_id, ...]
        self.check_index = {}
        for c in self.controls:
            for chk in c.checks:
                self.check_index.setdefault(chk, []).append(c.id)

    def control(self, cid):
        return next((c for c in self.controls if c.id == cid), None)


def available():
    """List of bundled framework aliases (canonical names)."""
    return sorted({v.rsplit(".", 1)[0] for v in ALIASES.values()})


def _read_bundled(filename):
    # Anchor on the top-level package; data ships as package-data (no __init__ needed in subdirs).
    path = resources.files("assure").joinpath("data", "frameworks", filename)
    return json.loads(path.read_text(encoding="utf-8"))


def load(name_or_path):
    """Resolve a framework by alias (e.g. 'cps234') or by path to a JSON pack."""
    if not name_or_path:
        raise FrameworkError("no framework specified")
    key = str(name_or_path).strip()

    # Explicit file path wins.
    if key.endswith(".json") and os.path.exists(key):
        try:
            return Framework(json.loads(open(key, encoding="utf-8").read()))
        except json.JSONDecodeError as e:
            raise FrameworkError(f"{key} is not valid JSON: {e}") from e

    alias = ALIASES.get(key.lower())
    if alias:
        return Framework(_read_bundled(alias))

    raise FrameworkError(
        f"unknown framework '{name_or_path}'. "
        f"Bundled: {', '.join(available())}; or pass a path to a framework-pack .json"
    )
