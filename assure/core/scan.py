"""Run Prowler against an AWS account, scoped to a framework's checks.

We only run the checks the framework actually maps (efficient + focused), then
map them to controls ourselves — so the framework need not be installed in Prowler.
"""
import glob
import os
import shutil
import subprocess
import tempfile


class ScanError(RuntimeError):
    pass


def prowler_available():
    return shutil.which("prowler") is not None


def run_prowler(framework, region=None, profile=None, extra_args=None):
    """Run Prowler for the framework's checks; return (csv_path, workdir).

    Caller is responsible for removing `workdir` when done reading csv_path.
    """
    prowler = shutil.which("prowler")
    if not prowler:
        raise ScanError(
            "prowler not found on PATH. Install it (`pip install aiopsone-assure[scan]` "
            "or `pip install prowler`), or run `assure report --in <findings.csv>` instead."
        )
    checks = sorted(framework.check_index)
    if not checks:
        raise ScanError(f"framework '{framework.id}' defines no automatable checks to scan")

    workdir = tempfile.mkdtemp(prefix="assure-scan-")
    cmd = [prowler, "aws", "-M", "csv",
           "--output-directory", workdir, "--output-filename", "assure-scan"]
    cmd += ["--check", *checks]
    if region:
        cmd += ["--region", region]
    if profile:
        cmd += ["--profile", profile]
    if extra_args:
        cmd += list(extra_args)

    try:
        # Prowler exits non-zero when findings FAIL — that's expected, not an error.
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError as e:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ScanError(f"could not execute prowler: {e}") from e
    except subprocess.TimeoutExpired:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ScanError("prowler scan timed out (>1h)") from None

    matches = glob.glob(os.path.join(workdir, "*.csv"))
    if not matches:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ScanError("prowler produced no CSV output — check AWS credentials / permissions")
    return matches[0], workdir
