"""assure — APRA compliance evidence for AWS, from your terminal.

  assure scan   --framework cps234 --region ap-southeast-2     # run Prowler, then report
  assure report --in findings.csv --framework cps234           # report from existing findings
  assure frameworks                                            # list bundled frameworks

Exit codes:  0 = no failing controls · 2 = one or more controls FAIL · 1 = error
"""
import argparse
import json
import os
import shutil
import sys

from . import __version__
from .core import frameworks, ingest, mapping, narrate, report

# AU-resident inference profile (data residency for APRA-regulated entities), current model.
DEFAULT_MODEL = os.environ.get("BEDROCK_MODEL_ID", "au.anthropic.claude-sonnet-4-6")
DEFAULT_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")


def _err(msg):
    print(f"assure: error: {msg}", file=sys.stderr)
    return 1


def _add_common(p):
    p.add_argument("--framework", default="cps234",
                   help="framework alias (cps234, cps230) or path to a framework-pack .json")
    p.add_argument("--engine", choices=["template", "bedrock"], default="template",
                   help="narrative engine (default: template / offline)")
    p.add_argument("--no-ai", action="store_true", help="force the deterministic template engine")
    p.add_argument("--model", default=DEFAULT_MODEL, help="Bedrock model id (with --engine bedrock)")
    p.add_argument("--region", default=DEFAULT_REGION, help="AWS region")
    p.add_argument("-o", "--output", default="assure-report",
                   help="output basename or path (default: assure-report)")
    p.add_argument("--format", choices=["pdf", "md", "both"], default="both",
                   help="report format (default: both)")
    p.add_argument("--json", action="store_true", help="print a machine-readable summary to stdout")
    p.add_argument("--exit-zero", action="store_true", help="always exit 0, even with failing controls")


def _outputs(base, fmt):
    """Resolve (md_path, pdf_path) honouring an explicit extension on base."""
    root, ext = os.path.splitext(base)
    if ext.lower() == ".md":
        return root + ".md", root + ".pdf"
    if ext.lower() == ".pdf":
        return root + ".md", root + ".pdf"
    return base + ".md", base + ".pdf"


def _generate(fw, results, ctx, args):
    ctx = dict(ctx)
    ctx["engine"] = "template" if args.no_ai else args.engine
    control_results = mapping.aggregate(fw, results)
    s = mapping.summarise(control_results)

    engine = "template" if args.no_ai else args.engine
    try:
        base_narrator = narrate.get_narrator(engine, args.model, args.region)
    except RuntimeError as e:
        return _err(str(e))

    # Memoise per control so md + pdf reuse one narrative (no double Bedrock cost).
    _cache = {}

    def narrator(res):
        if res.control.id not in _cache:
            _cache[res.control.id] = base_narrator(res)
        return _cache[res.control.id]

    md = report.build_markdown(fw, control_results, ctx, narrator)
    md_path, pdf_path = _outputs(args.output, args.format)
    written = []

    if args.format in ("md", "both"):
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        written.append(md_path)

    if args.format in ("pdf", "both"):
        # Re-narrate via HTML builder (same narrator) so AI text isn't regenerated twice
        # for bedrock: build_html calls narrator again — acceptable for v1 (cache later).
        html_doc = report.build_html(fw, control_results, ctx, narrator)
        try:
            report.render_pdf(html_doc, pdf_path)
            written.append(pdf_path)
        except report.PDFError as e:
            if args.format == "pdf":
                return _err(str(e))
            print(f"assure: warning: PDF skipped ({e})", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "framework": fw.id, "score": s["score"], "counts": {
                "fail": s["fail"], "pass": s["pass"], "manual": s["manual"],
                "not_assessed": s["not_assessed"], "total": s["total"],
            }, "outputs": written,
        }, indent=2))
    else:
        print(f"✔ {fw.name}: {s['score']}% automated "
              f"({s['pass']} pass · {s['fail']} fail · {s['manual']} manual"
              + (f" · {s['not_assessed']} not-assessed" if s['not_assessed'] else "") + ")")
        for w in written:
            print(f"  → {w}")

    if s["fail"] and not args.exit_zero:
        return 2
    return 0


def cmd_report(args):
    try:
        fw = frameworks.load(args.framework)
    except frameworks.FrameworkError as e:
        return _err(str(e))
    if not os.path.exists(args.input):
        return _err(f"findings file not found: {args.input}")
    try:
        results, ctx = ingest.load(args.input)
    except ingest.IngestError as e:
        return _err(str(e))
    return _generate(fw, results, ctx, args)


def cmd_scan(args):
    from .core import scan
    try:
        fw = frameworks.load(args.framework)
    except frameworks.FrameworkError as e:
        return _err(str(e))
    print(f"Running Prowler for {fw.name} ({len(fw.check_index)} checks) in {args.region}…",
          file=sys.stderr)
    try:
        csv_path, workdir = scan.run_prowler(fw, region=args.region, profile=args.profile)
    except scan.ScanError as e:
        return _err(str(e))
    try:
        results, ctx = ingest.load(csv_path)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return _generate(fw, results, ctx, args)


def cmd_frameworks(args):
    for name in frameworks.available():
        fw = frameworks.load(name)
        print(f"{name:10s} {fw.name}  ({len(fw.controls)} controls, "
              f"{len(fw.check_index)} checks)")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="assure", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"assure {__version__}")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="run Prowler against an AWS account, then build the report")
    _add_common(sp)
    sp.add_argument("--profile", default=None, help="AWS profile to use for the scan")
    sp.set_defaults(func=cmd_scan)

    rp = sub.add_parser("report", help="build the report from an existing findings file")
    rp.add_argument("--in", dest="input", required=True, help="Prowler CSV/JSON findings file")
    _add_common(rp)
    rp.set_defaults(func=cmd_report)

    fp = sub.add_parser("frameworks", help="list bundled frameworks")
    fp.set_defaults(func=cmd_frameworks)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
