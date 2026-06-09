"""Turn a control's structured result into a board-ready narrative paragraph.

Two engines:
  template  deterministic, offline, uses the framework's rationale/remediation (default)
  bedrock   sends each control's structured data to Claude on Amazon Bedrock (AU-resident)
"""
from .mapping import FAIL, PASS, MANUAL, NOT_ASSESSED

SYSTEM_PROMPT = (
    "You are an APRA compliance analyst. Write a concise, board-ready paragraph "
    "(3-5 sentences) for one control, in plain professional English for a risk committee. "
    "State the compliance position, what the evidence shows, why it matters under the "
    "standard, and the priority remediation. Do not invent findings beyond those provided."
)


def narrate_template(res):
    c = res.control
    if res.status == FAIL:
        n = len(res.fails)
        return (f"**Not compliant.** {n} issue(s) detected against this control. "
                f"{c.rationale} {c.impact} Priority remediation: {c.remediation}")
    if res.status == PASS:
        return (f"**Compliant.** All {res.pass_count} automated check(s) for this control "
                f"passed. {c.rationale}")
    if res.status == NOT_ASSESSED:
        return ("**Not assessed.** This control is automatable but no matching checks were "
                f"present in the supplied findings. Re-run the scan to evidence it. {c.rationale}")
    return ("**Manual assessment required.** "
            f"{c.rationale} This obligation is not observable from AWS APIs and must be "
            f"evidenced via documentation/process: {c.remediation}")


def _narrate_bedrock(client, model_id, res):
    c = res.control
    findings = "\n".join(f"- {f['detail']} ({f['check']})" for f in res.fails) or "None"
    user = (
        f"Control: {c.name} (paragraph {c.paragraph})\n"
        f"Status: {res.status}\n"
        f"Requirement: {c.description}\n"
        f"Rationale: {c.rationale}\n"
        f"Findings:\n{findings}\n"
        f"Remediation guidance: {c.remediation}\n"
    )
    resp = client.converse(
        modelId=model_id,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": user}]}],
        inferenceConfig={"maxTokens": 400, "temperature": 0.2},
    )
    return resp["output"]["message"]["content"][0]["text"].strip()


def get_narrator(engine="template", model=None, region=None):
    """Return a callable: ControlResult -> narrative str. Falls back to template on any AI error."""
    if engine != "bedrock":
        return narrate_template

    try:
        import boto3  # deferred: template mode needs no AWS deps
    except ImportError as e:
        raise RuntimeError(
            "Bedrock engine needs boto3 — install with `pip install aiopsone-assure[ai]` "
            "or use --no-ai for the deterministic template engine."
        ) from e

    client = boto3.client("bedrock-runtime", region_name=region)

    def _narrate(res):
        # Only AI-narrate controls with real finding data (FAIL/PASS). MANUAL and
        # NOT_ASSESSED have no evidence to reason over — the model would otherwise
        # invent a verdict for controls it can't assess. Use the deterministic
        # template there (also cheaper: fewer Bedrock calls).
        if res.status in (MANUAL, NOT_ASSESSED):
            return narrate_template(res)
        try:
            return _narrate_bedrock(client, model, res)
        except Exception as e:  # never hard-fail a report on an AI hiccup
            return f"_(AI unavailable: {e}; template fallback)_ " + narrate_template(res)

    return _narrate
