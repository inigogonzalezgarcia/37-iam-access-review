"""Command line: `demo` writes the fictional clearing house to sample_data/ and builds the outputs; `review` runs on your own exports."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import report, simulate
from .checks import overall, review, run_all, summary
from .model import load, parse_dt

OUTPUTS = ("report.html", "access-review.md", "leavers.csv", "movers.csv", "orphans.csv", "privileged.csv", "service-accounts.csv", "recert.csv",
           "actions.csv", "findings.csv")


def run(data: Path, out: Path, title: str, as_of: datetime | None = None) -> dict:
    d = load(data, as_of)
    rv = review(d)
    findings = run_all(d, rv)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(d, rv, findings, title), encoding="utf-8")
    (out / "access-review.md").write_text(report.pack_md(d, rv, findings, title), encoding="utf-8")
    report.write_leavers(d, rv, out / "leavers.csv")
    report.write_movers(d, rv, out / "movers.csv")
    report.write_orphans(d, rv, out / "orphans.csv")
    report.write_privileged(d, rv, out / "privileged.csv")
    report.write_service(d, rv, out / "service-accounts.csv")
    report.write_recert(d, rv, out / "recert.csv")
    report.write_actions(findings, out / "actions.csv")
    report.write_findings(findings, out / "findings.csv")
    sm = summary(d, rv)
    sm.update(overall=overall(findings), critical=sum(f.severity == "critical" for f in findings), warning=sum(f.severity == "warning" for f in findings))
    return sm


def _when(value: str) -> datetime:
    d = parse_dt(value)
    if not d:
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM'): {value}")
    return d


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="iamreview", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    dm = sub.add_parser("demo", help="write the fictional clearing house to sample_data/ and build the outputs")
    dm.add_argument("--data", type=Path, default=Path("sample_data"))
    dm.add_argument("--out", type=Path, default=Path("output"))
    rv = sub.add_parser("review", help="build the outputs from your own exports")
    rv.add_argument("data", type=Path, nargs="?", help="folder with hr.csv, ad-users.csv and/or entra-users.csv, and the optional files")
    rv.add_argument("--data", dest="data_opt", type=Path, help="same as the positional folder")
    rv.add_argument("--out", type=Path, default=Path("output"))
    rv.add_argument("--title", default="Monthly access review")
    rv.add_argument("--as-of", type=_when, help="review time (default: settings.json, or now)")
    a = p.parse_args(argv)
    if a.cmd == "demo":
        simulate.write(a.data)
        sm = run(a.data, a.out, f"{simulate.ORG} · Monthly access review, September 2026")
    else:
        folder = a.data or a.data_opt
        if not folder:
            print("error: give the folder with the exports", file=sys.stderr)
            return 2
        try:
            sm = run(folder, a.out, a.title, a.as_of)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    print(f"{sm['overall'].upper()} · {sm['people']} people, {sm['accounts']} accounts · leavers still enabled {sm['leavers_access']} · "
          f"movers kept access {sm['movers_kept']} · orphans {sm['orphans']} · inactive {sm['inactive']} · standing roles {sm['standing']} · "
          f"Tier 0 unapproved {sm['tier0_unapproved']} · PAM overdue {sm['pam_overdue']} · recert {sm['recert_done']:.0f}% done, "
          f"{sm['revoke_pending']} revokes pending, {sm['rubber']} rubber-stamp · {sm['critical']} critical, {sm['warning']} warnings")
    print(f"outputs in {a.out}/: {', '.join(OUTPUTS)}")
    return 0
