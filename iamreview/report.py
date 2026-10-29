"""Outputs: report.html, access-review.md (the pack for the monthly IAM service review, with the controls written the way an auditor reads
them), and the CSVs: leavers, movers, orphans, privileged, service accounts, recertification, actions and findings."""
from __future__ import annotations

import csv
import html
from datetime import datetime
from pathlib import Path

from .checks import (_n, AREAS, CRITICAL, INFO, VERDICT, WARNING, Finding, area_status, now_label, overall, person_label, summary)
from .model import Account, Data, days

e = html.escape


# ---------------------------------------------------------------- csv

def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _t(v, f="%Y-%m-%d %H:%M") -> str:
    if not v:
        return ""
    return v.strftime(f if isinstance(v, datetime) else "%Y-%m-%d")


def _iss(r: dict) -> str:
    return " | ".join(f"{i.code} {i.text}" for i in r["issues"])


def write_findings(findings: list[Finding], path: Path) -> None:
    _w(path, ["severity", "area", "code", "subject", "detail", "next_step", "owner", "items"],
       [[f.severity, f.area, f.code, f.subject, f.detail, f.fix, f.owner, "; ".join(f.items)] for f in findings])


def write_actions(findings: list[Finding], path: Path) -> None:
    _w(path, ["ref", "action", "next_step", "owner", "severity", "due", "done"],
       [[f.code, f.subject, f.fix, f.owner, f.severity, "", ""] for f in findings if f.severity != INFO])


def write_leavers(d: Data, rv: dict, path: Path) -> None:
    out = []
    for r in rv["leavers"]:
        p = r["person"]
        out.append([p.employee_id, p.name, p.department, _t(p.end), days(p.end, d.today) if p.end else "", _t(r["due"]),
                    "; ".join(a.label for a in r["accounts"]), "; ".join(a.label for a in r["enabled"]), _t(r["last"]),
                    "; ".join(f"{a.label} {_t(a.last_logon)}" for a in r["after"]), r["groups"], "; ".join(r["priv"]), r["verdict"], _iss(r)])
    _w(path, ["employee_id", "name", "department", "end_date", "days_since_end", "disable_due", "accounts", "enabled_accounts", "last_sign_in",
              "signed_in_after_end", "groups_tier0_to_2", "privileged", "verdict", "issues"], out)


def write_movers(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["employee_id", "name", "from_department", "to_department", "moved", "grace_until", "kept_entitlements", "kept_tiers", "verdict", "issues"],
       [[r["person"].employee_id, r["person"].name, r["person"].previous_department, r["person"].department, _t(r["person"].moved), _t(r["grace"]),
         "; ".join(sorted({e.group for _, e in r["kept"]})), "; ".join(sorted({str(e.tier) for _, e in r["kept"]})), r["verdict"], _iss(r)]
        for r in rv["movers"]])


def write_orphans(d: Data, rv: dict, path: Path) -> None:
    out = []
    for r in rv["accounts"]:
        codes = {i.code for i in r["issues"]}
        if not codes & {"ACC-01", "ACC-02"}:
            continue
        a: Account | None = r["account"]
        kind = "orphan" if "ACC-01" in codes else "duplicate employee ID"
        out.append([a.name if a else "", a.directory if a else "HR", kind, d.employee_id_of(a) if a else r["person"].employee_id,
                    person_label(r["person"]), "yes" if a and a.enabled else "", _t(a.created) if a else "", _t(d.last_activity(a)) if a else "",
                    "; ".join(d.groups_of(a)) if a else "", a.description if a else "", r["verdict"], _iss(r)])
    _w(path, ["account", "directory", "kind", "employee_id", "hr_person", "enabled", "created", "last_activity", "groups", "description", "verdict",
              "issues"], out)


def write_privileged(d: Data, rv: dict, path: Path) -> None:
    out = []
    for r in rv["privileged"]:
        ro = r["role"]
        p = r["person"]
        out.append([r["source"], r["principal"], r["what"], r["how"], _t(ro.start) if ro else "", _t(ro.end) if ro else "",
                    "yes" if r["break_glass"] else "", person_label(p), ("left" if p.left(d.today) else "active") if p else "",
                    "" if r["mfa"] is None else ("yes" if r["mfa"] else "no"), _t(r["last"]), "yes" if r["vaulted"] else "no", r["verdict"], _iss(r)])
    for r in rv["pam"]:
        if r["pam"]:
            x = r["pam"]
            out.append(["PAM vault", x.account, f"{x.safe} · {x.platform}", "vaulted", "", "", "", x.owner, "", "", _t(x.last_used), "yes",
                        r["verdict"], _iss(r)])
        else:
            out.append(["PAM vault", r["account"].name, "", "not vaulted", "", "", "", person_label(d.person_of(r["account"])), "", "",
                        _t(d.last_activity(r["account"])), "no", r["verdict"], _iss(r)])
    _w(path, ["source", "principal", "role_or_group", "assignment", "start", "end", "break_glass", "person", "person_status", "mfa_registered",
              "last_activity", "vaulted", "verdict", "issues"], out)


def write_service(d: Data, rv: dict, path: Path) -> None:
    out = []
    for r in rv["service"]:
        x, a = r["svc"], r["account"]
        out.append([x.account, x.directory or (a.directory if a else ""), "yes" if r["found"] else "no", "yes" if a and a.enabled else "no", x.owner,
                    r["owner"].name if r["owner"] else "", r["owner_status"], x.purpose, "yes" if x.interactive else "no", _t(r["interactive_last"]),
                    _t(d.last_activity(a)) if a else "", "yes" if a and a.pwd_never_expires else "no", "yes" if r["vaulted"] else "no", r["verdict"],
                    _iss(r)])
    for r in rv["accounts"]:
        if r["kind"] == "service":
            a = r["account"]
            out.append([a.name, a.directory, "yes", "yes" if a.enabled else "no", "", "", "not registered", a.description, "", "", _t(d.last_activity(a)),
                        "yes" if a.pwd_never_expires else "no", "yes" if d.vaulted(a) else "no", r["verdict"], _iss(r)])
    _w(path, ["account", "directory", "found", "enabled", "owner", "owner_name", "owner_status", "purpose", "interactive_allowed",
              "last_interactive_sign_in", "last_activity", "password_never_expires", "vaulted", "verdict", "issues"], out)


def write_recert(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["campaign", "item", "group", "application", "tier", "user", "reviewer", "decision", "decided_on", "due", "removed_on", "still_member",
              "status", "rubber_stamp", "issues"],
       [[r["item"].campaign, r["item"].item, r["item"].group, r["application"], r["tier"], r["item"].user, r["item"].reviewer, r["item"].decision,
         _t(r["item"].decided, "%Y-%m-%d %H:%M:%S"), _t(r["item"].due), _t(r["item"].removed), "yes" if r["still"] else "no", r["status"],
         "yes" if r["rubber"] else "", _iss(r)] for r in rv["recert"]])


# ---------------------------------------------------------------- the monthly pack

CONTROLS = [  # id, statement, codes, population key
    ("AC-01", "Leavers' accounts are disabled within {leaver_grace_days} day(s) of the HR end date", ("LVR-01",), "leavers"),
    ("AC-02", "Leavers' group memberships (tier 0 to 2) and directory roles are removed", ("LVR-02",), "leavers"),
    ("AC-03", "Movers lose the access of their previous department within {mover_grace_days} days", ("MOV-01",), "movers"),
    ("AC-04", "Joiners get access from their start date, with a manager recorded", ("JNR-01", "JNR-02"), "joiners"),
    ("AC-05", "Every enabled account maps to one HR record or to a registered service account", ("ACC-01", "ACC-02"), "accounts"),
    ("AC-06", "Accounts unused for {inactive_days} days are disabled; human passwords expire", ("ACC-03", "ACC-04"), "accounts"),
    ("AC-07", "Privileged directory roles are eligible through PIM, not standing (break-glass excepted), and held with MFA", ("PRV-01", "PRV-02"),
     "privileged"),
    ("AC-08", "Tier 0 group membership is limited to the approved list", ("PRV-03",), "privileged"),
    ("AC-09", "Privileged credentials are vaulted and rotated every {pam_rotation_days} days", ("PAM-01", "PAM-02"), "pam"),
    ("AC-10", "Service accounts have an owner in employment and no interactive sign-in", ("SVC-01", "SVC-02"), "service"),
    ("AC-11", "Guests have a sponsor and signed in within {guest_inactive_days} days", ("GST-01", "GST-02"), "guests"),
    ("AC-12", "Recertification items are decided by the due date and revokes removed within {revoke_sla_days} days; reviews are genuine",
     ("REC-01", "REC-02", "REC-03"), "recert"),
    ("AC-13", "Entitlements are recertified at the frequency of their tier", ("REC-04",), "entitlements"),
]
TODO = "**[TO COMPLETE]**"


def _population(d: Data, rv: dict, k: str) -> str:
    sm = summary(d, rv)
    return {"leavers": f"{len(rv['leavers'])} leavers ({sm['leavers_period']} in the period)",
            "movers": f"{len(rv['movers'])} movers", "joiners": f"{len(rv['joiners'])} joiners",
            "accounts": f"{sm['accounts']} accounts", "privileged": f"{sm['priv_holders']} privileged principals, {len(d.roles)} role assignments",
            "pam": f"{len(d.pam)} vaulted accounts", "service": f"{len(d.service)} registered service accounts", "guests": f"{sm['guests']} guests",
            "recert": f"{sm['recert_items']} items", "entitlements": f"{len(d.catalogue)} entitlements"}[k]


def _exceptions(rv: dict, codes: tuple[str, ...]) -> list:
    out = {}
    for name in ("leavers", "movers", "joiners", "accounts", "privileged", "pam", "service", "guests", "recert", "reviewers", "entitlements"):
        for r in rv[name]:
            for i in r["issues"]:
                if i.code in codes and i.severity != INFO:
                    out.setdefault(i.text, i)
    return list(out.values())


def pack_md(d: Data, rv: dict, findings: list[Finding], title: str) -> str:
    s, sm, st = d.settings, summary(d, rv), area_status(findings)
    start = s.period_start
    out = [f"# {title}", "",
           f"> Generated by iamreview on {now_label(d.as_of)} from the exports listed under *Scope and evidence*. Read-only: nothing was changed in "
           f"the directories. Sections marked {TODO} are for the service owner before the pack is shared.", "",
           f"**Overall status: {overall(findings).upper()}**", "",
           "| Area | Status | To act on |", "|---|---|---|"]
    for a in AREAS:
        n = sum(f.area == a and f.severity != INFO for f in findings)
        out.append(f"| {a} | {'OK' if st[a] == 'ok' else VERDICT[st[a]].upper()} | {n} |")
    out += ["", "## Headlines", "",
            f"- {sm['people']} people in HR ({sm['active']} active), {sm['accounts']} accounts reviewed ({sm['ad']} Active Directory, {sm['entra']} Entra ID, "
            f"{sm['guests']} guests).",
            f"- Leavers: {sm['leavers_period']} in the period; {sm['leavers_access']} still have an enabled account after the grace.",
            f"- Movers: {sm['movers_kept']} kept access of their previous department beyond {s.mover_grace_days} days. "
            f"Joiners: {sm['joiners']}, {sm['joiners_issues']} with an exception.",
            f"- Accounts: {_n(sm['orphans'], 'orphan')}, {sm['duplicates']} on a duplicate employee ID, {sm['inactive']} inactive over {s.inactive_days} days, "
            f"{sm['pwd_never']} human accounts with a password that never expires.",
            f"- Privileged: {_n(sm['standing'], 'standing role assignment')} outside PIM, {sm['no_mfa']} privileged without MFA, "
            f"{_n(sm['tier0_unapproved'], 'Tier 0 member')} not approved, {_n(sm['pam_overdue'], 'vaulted password')} overdue, "
            f"{_n(sm['not_vaulted'], 'admin account')} not vaulted.",
            f"- Recertification: {sm['recert_done']:.0f}% decided ({sm['recert_decided']} of {sm['recert_items']}), {sm['recert_overdue']} overdue, "
            f"{_n(sm['revoke_pending'], 'revoke')} not actioned, {_n(sm['rubber'], 'reviewer')} approving {sm['rubber_items']} items in minutes, "
            f"{_n(sm['ent_overdue'], 'entitlement')} overdue.", "",
            "## Scope and evidence", "",
            f"- Period: {start:%d %b %Y} to {d.today:%d %b %Y}" if start else f"- Review date: {d.today:%d %b %Y}",
            f"- Organisation: {s.organisation}", "",
            "| Source | File | Records |", "|---|---|---|"]
    names = {"hr.csv": "HR roster", "ad-users.csv": "Active Directory users (Get-ADUser)", "entra-users.csv": "Entra ID users (Get-MgUser, signInActivity)",
             "memberships.csv": "Group memberships (Get-ADGroupMember, Get-MgGroupTransitiveMember)", "entitlements.csv": "Entitlement catalogue",
             "privileged-roles.csv": "Entra ID roles: active instances and PIM eligibilities", "pam-accounts.csv": "PAM vault accounts",
             "service-register.csv": "Service account register", "recert-results.csv": "Recertification campaign results"}
    out += [f"| {names.get(k, k)} | `{k}` | {v} |" for k, v in d.sources.items()]
    out += ["", "Policy parameters used (from `settings.json`):", "",
            f"- leaver grace {s.leaver_grace_days} day(s); mover grace {s.mover_grace_days} days; inactivity {s.inactive_days} days (guests "
            f"{s.guest_inactive_days}, privileged {s.privileged_inactive_days}); PAM rotation {s.pam_rotation_days} days"
            + (" (" + ", ".join(f"{k} {v}" for k, v in s.pam_rotation_by_platform.items()) + ")" if s.pam_rotation_by_platform else "")
            + f"; revoke SLA {s.revoke_sla_days} days;",
            f"- roles that must be eligible, not standing: {', '.join(s.pim_roles)};",
            f"- break-glass accounts: {', '.join(s.break_glass) or 'none'}; approved Tier 0: {', '.join(s.approved_tier0) or 'none'}.", "",
            "## Controls tested", "", "| Control | Statement | Population | Exceptions | Result |", "|---|---|---|---|---|"]
    for cid, stmt, codes, pop in CONTROLS:
        ex = _exceptions(rv, codes)
        crit = any(i.severity == CRITICAL for i in ex)
        res = "Not effective" if crit else "Exceptions" if ex else "Effective"
        out.append(f"| {cid} | {stmt.format(**vars(s))} | {_population(d, rv, pop)} | {len(ex)} | {res} |")
    out += ["", "\"Effective\" means no exception in the exports for the period; it does not test the data the exports do not contain.", "",
            "## Exceptions by control", ""]
    for cid, stmt, codes, _ in CONTROLS:
        ex = _exceptions(rv, codes)
        if not ex:
            continue
        out += [f"### {cid} · {stmt.format(**vars(s))}", ""]
        out += [f"- **{i.code}** ({i.severity}) {i.text.replace('|', '/')}" for i in sorted(ex, key=lambda i: (i.severity != CRITICAL, i.code, i.text))[:25]]
        if len(ex) > 25:
            out.append(f"- … and {len(ex) - 25} more in the CSV files.")
        out.append("")
    out += ["## Actions", "", "| Ref | Action | Next step | Owner | Due |", "|---|---|---|---|---|"]
    out += [f"| {f.code} | {f.subject} | {f.fix} | {f.owner} | {TODO if f.severity == CRITICAL else ''} |" for f in findings if f.severity != INFO]
    out += ["", "## Recertification by reviewer", "", "| Reviewer | Items | Decided | Approved | Revoked | Time taken | Flag |", "|---|---|---|---|---|---|---|"]
    for r in rv["reviewers"]:
        span = "–" if r["span"] is None else f"{round(r['span'])} min" if r["span"] < 120 else f"{r['span'] / 1440:.1f} days"
        out.append(f"| {r['reviewer'] or '?'} | {r['items']} | {r['decided']} | {r['approved']} | {r['revoked']} | {span} | "
                   f"{'rubber-stamp' if r['issues'] else ''} |")
    out += ["", "## Notes for the auditor", "",
            "- Evidence: the CSV files in this folder are the per-item evidence for each control (`leavers.csv`, `movers.csv`, `orphans.csv`, "
            "`privileged.csv`, `service-accounts.csv`, `recert.csv`); `findings.csv` lists every exception.",
            "- Sign-in dates: Active Directory `lastLogonTimestamp` replicates with a lag of up to 14 days; Entra ID sign-in activity is updated "
            "within hours to a day. Inactivity is measured on the most recent of the two.",
            f"- Compensating controls or accepted risks: {TODO}", "",
            "## Sign-off", "", f"- Reviewed by (IAM operations): {TODO}", f"- Approved by (IAM service owner): {TODO}", f"- Date: {TODO}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:26px}
.overall{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:99px;font-weight:700;border:2px solid currentColor}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}
.area .lbl{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:4px}.area .cnt{display:block;font-size:13px;color:var(--muted);margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}
.area.critical,.area.warning,.area.ok{color:inherit}
.pill.clean{color:var(--ok)}.pill.follow-up{color:var(--warn)}.pill.action-needed{color:var(--bad)}
td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);min-width:200px;max-width:380px}td.sm{font-size:13px}
.brk{overflow-wrap:anywhere;word-break:break-word}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--line);min-width:120px}
.bar span{display:block;height:100%}.b-ok{background:var(--ok)}.b-rv{background:var(--bad)}.b-pd{background:var(--warn)}
footer{margin-top:40px;font-size:13px}
"""


def _pill(cls: str, text: str) -> str:
    return f"<span class='pill {cls}'>{e(text)}</span>"


def _vpill(v: str) -> str:
    return _pill(v.replace(" ", "-"), v.upper())


def _issues(r: dict) -> str:
    xs = sorted(r["issues"], key=lambda x: (x.severity != CRITICAL, x.severity == INFO))
    return "<br>".join(f"<span class='{x.severity}'>●</span> <b>{e(x.code)}</b> {e(x.text)}" for x in xs) or "<span class='muted'>–</span>"


def _table(head: list[str], rows: list[str]) -> str:
    return "<div class='wrap'><table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + "".join(rows) + "</table></div>"


def render_html(d: Data, rv: dict, findings: list[Finding], title: str) -> str:
    s, sm, st = d.settings, summary(d, rv), area_status(findings)
    ov = overall(findings)
    period = f"{s.period_start:%d %b} to {d.today:%d %b %Y}" if s.period_start else f"{d.today:%d %b %Y}"
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>Joiners, movers and leavers, orphan and inactive accounts, privileged access, PAM, service and guest "
         f"accounts and the recertification campaign · {period} · as of {now_label(d.as_of)}</p>",
         f"<span class='overall {'critical' if ov == 'action needed' else 'warning' if ov == 'follow up' else 'ok'}'>Overall: {e(ov.upper())}</span>"
         "<div class='tiles'>"]
    tiles = [("People", str(sm["people"]), f"{sm['accounts']} accounts"), ("Leavers enabled", str(sm["leavers_access"]), f"of {sm['leavers_period']} leavers"),
             ("Movers kept access", str(sm["movers_kept"]), f"after {s.mover_grace_days} days"), ("Orphans", str(sm["orphans"]), f"{sm['duplicates']} duplicates"),
             ("Inactive", str(sm["inactive"]), f"> {s.inactive_days} days"), ("Standing roles", str(sm["standing"]), "outside PIM"),
             ("Tier 0 unapproved", str(sm["tier0_unapproved"]), f"{sm['no_mfa']} privileged without MFA"),
             ("PAM overdue", str(sm["pam_overdue"]), f"{sm['not_vaulted']} not vaulted"),
             ("Recert done", f"{sm['recert_done']:.0f}%", f"{sm['recert_overdue']} overdue"),
             ("Revokes pending", str(sm["revoke_pending"]), f"SLA {s.revoke_sla_days} days")]
    h += [f"<div class='tile'><span class='muted'>{e(a)}</span><b>{e(x)}</b><span class='muted'>{e(y)}</span></div>" for a, x, y in tiles]
    h.append("</div><h2>Status by area</h2><div class='areas'>")
    for a in AREAS:
        n = sum(f.area == a and f.severity != INFO for f in findings)
        h.append(f"<div class='area {st[a]}'><span class='lbl'>{e(a)}</span>{_pill(st[a], 'OK' if st[a] == 'ok' else VERDICT[st[a]].upper())}"
                 f"<span class='cnt'>{n} to act on</span></div>")
    h.append("</div>")
    crit = [f for f in findings if f.severity == CRITICAL]
    if crit:
        h.append("<h2>Fix first</h2>")
        h.append(_table(["Subject", "What", "Next step", "Owner"],
                        [f"<tr><td><b>{e(f.subject)}</b><br><span class='muted'>{e(f.area)} · {e(f.code)}</span></td><td class='sm'>{e(f.detail)}</td>"
                         f"<td class='fix'>{e(f.fix)}</td><td class='nw'>{e(f.owner)}</td></tr>" for f in crit]))
    # leavers
    lv = [r for r in rv["leavers"] if r["severity"] or r["enabled"]]
    h.append(f"<h2>Leavers</h2><p class='muted'>{sm['leavers_period']} leavers in the period; listed: the ones with an account enabled or access left. "
             "Every leaver is in leavers.csv.</p>")
    h.append(_table(["Person", "Left", "Enabled accounts", "Last sign-in", "Status", "Issues"],
                    [f"<tr><td><b>{e(r['person'].name)}</b><br><span class='muted'>{e(r['person'].employee_id)} · {e(r['person'].department)}</span></td>"
                     f"<td class='nw'>{_t(r['person'].end)}</td><td class='sm'>{e(', '.join(a.label for a in r['enabled']) or '–')}</td>"
                     f"<td class='nw'>{_t(r['last'])}</td><td>{_vpill(r['verdict'])}</td><td class='sm'>{_issues(r)}</td></tr>" for r in lv]))
    # movers and joiners
    mj = [r for r in rv["movers"] + rv["joiners"] if r["issues"]]
    if mj:
        h.append("<h2>Movers and joiners</h2>")
        h.append(_table(["Person", "Event", "Status", "Issues"],
                        [f"<tr><td><b>{e(r['person'].name)}</b><br><span class='muted'>{e(r['person'].employee_id)} · {e(r['person'].department)}</span></td>"
                         f"<td class='nw'>{'moved ' + _t(r['person'].moved) if 'kept' in r else 'starts ' + _t(r['person'].start)}</td>"
                         f"<td>{_vpill(r['verdict'])}</td><td class='sm'>{_issues(r)}</td></tr>" for r in mj]))
    # accounts
    acc = [r for r in rv["accounts"] if r["issues"]]
    h.append("<h2>Accounts</h2><p class='muted'>Orphans and duplicates (orphans.csv), accounts inactive over the policy and human accounts with a "
             "password that never expires.</p>")
    h.append(_table(["Account", "Kind", "HR", "Last activity", "Issues"],
                    [f"<tr><td class='nw'><b>{e(r['account'].name if r['account'] else '–')}</b><br><span class='muted'>"
                     f"{e(r['account'].directory if r['account'] else 'HR')}</span></td><td>{e(r['kind'])}</td>"
                     f"<td class='sm'>{e(person_label(r['person']))}</td><td class='nw'>{_t(d.last_activity(r['account'])) if r['account'] else ''}</td>"
                     f"<td class='sm'>{_issues(r)}</td></tr>" for r in sorted(acc, key=lambda r: (r['severity'] != CRITICAL, r['issues'][0].code))]))
    # privileged
    h.append("<h2>Privileged access</h2><p class='muted'>Entra ID roles (active and eligible) and Tier 0 group members, with MFA, last sign-in and "
             "whether the account is in the vault.</p>")
    h.append(_table(["Principal", "Role or group", "Assignment", "Person", "MFA", "Last sign-in", "Vaulted", "Issues"],
                    [f"<tr><td class='brk'><b>{e(r['principal'])}</b>{'<br><span class=muted>break-glass</span>' if r['break_glass'] else ''}</td>"
                     f"<td>{e(r['what'])}</td><td class='nw'>{e(r['how'])}</td><td class='sm'>{e(person_label(r['person']))}"
                     f"{' <span class=critical>left</span>' if r['person'] and r['person'].left(d.today) else ''}</td>"
                     f"<td>{'–' if r['mfa'] is None else 'yes' if r['mfa'] else '<span class=critical>no</span>'}</td>"
                     f"<td class='nw'>{_t(r['last'])}</td><td>{'yes' if r['vaulted'] else 'no'}</td><td class='sm'>{_issues(r)}</td></tr>"
                     for r in rv["privileged"]]))
    pam = [r for r in rv["pam"] if r["issues"]]
    if pam:
        h.append("<h2>PAM vault</h2>")
        h.append(_table(["Account", "Safe · platform", "Last change", "Policy", "Issues"],
                        [f"<tr><td class='nw'><b>{e(r['pam'].account if r['pam'] else r['account'].name)}</b>"
                         f"{'<br><span class=muted>' + e(r['pam'].address) + '</span>' if r['pam'] else ''}</td>"
                         f"<td class='sm'>{e(r['pam'].safe + ' · ' + r['pam'].platform) if r['pam'] else 'not vaulted'}</td>"
                         f"<td class='nw'>{_t(r['pam'].last_change) if r['pam'] else ''}</td><td class='num'>{r['rotation'] or ''}</td>"
                         f"<td class='sm'>{_issues(r)}</td></tr>" for r in pam]))
    # service and guests
    h.append("<h2>Service accounts</h2>")
    h.append(_table(["Account", "Purpose", "Owner", "Interactive", "Last interactive", "Vaulted", "Status", "Issues"],
                    [f"<tr><td class='nw'><b>{e(r['svc'].account)}</b></td><td class='sm'>{e(r['svc'].purpose)}</td>"
                     f"<td class='sm'>{e(r['owner'].name if r['owner'] else (r['svc'].owner or '–'))}<br><span class='muted'>{e(r['owner_status'])}</span></td>"
                     f"<td>{'allowed' if r['svc'].interactive else 'not allowed'}</td><td class='nw'>{_t(r['interactive_last'])}</td>"
                     f"<td>{'yes' if r['vaulted'] else 'no'}</td><td>{_vpill(r['verdict'])}</td><td class='sm'>{_issues(r)}</td></tr>" for r in rv["service"]]))
    gs = [r for r in rv["guests"] if r["issues"]]
    if gs:
        h.append(f"<h2>Guests</h2><p class='muted'>{sm['guests']} guests; listed: the ones inactive over {s.guest_inactive_days} days or without a sponsor.</p>")
        h.append(_table(["Guest", "Created", "Last sign-in", "Sponsor", "Issues"],
                        [f"<tr><td class='sm brk'><b>{e(r['account'].display_name or r['account'].name)}</b><br><span class='muted'>{e(r['account'].name)}</span></td>"
                         f"<td class='nw'>{_t(r['account'].created, '%Y-%m-%d')}</td><td class='nw'>{_t(r['account'].last_logon)}</td>"
                         f"<td class='sm brk'>{e(', '.join(r['account'].sponsors) or '–')}</td><td class='sm'>{_issues(r)}</td></tr>" for r in gs]))
    # recertification
    h.append("<h2>Recertification</h2><p class='muted'>Per reviewer: approved (green), revoked (red) and no decision (amber); time from the first to "
             "the last decision.</p>")
    rows = []
    for r in rv["reviewers"]:
        w = lambda n: f"{100 * n / r['items']:.1f}%" if r["items"] else "0"  # noqa: E731
        span = "–" if r["span"] is None else f"{round(r['span'])} min" if r["span"] < 120 else f"{r['span'] / 1440:.1f} days"
        rows.append(f"<tr><td class='nw'><b>{e(r['reviewer'] or '?')}</b></td><td class='num'>{r['items']}</td>"
                    f"<td><div class='bar'><span class='b-ok' style='width:{w(r['approved'])}'></span><span class='b-rv' style='width:{w(r['revoked'])}'>"
                    f"</span><span class='b-pd' style='width:{w(r['pending'])}'></span></div></td><td class='num'>{r['approved']} / {r['revoked']} / {r['pending']}</td>"
                    f"<td class='num'>{span}</td><td class='sm'>{_issues(r)}</td></tr>")
    h.append(_table(["Reviewer", "Items", "Decisions", "Approve / revoke / none", "Time taken", "Issues"], rows))
    rec = [r for r in rv["recert"] if any(i.severity != INFO for i in r["issues"]) and any(i.code == "REC-02" for i in r["issues"])]
    if rec:
        h.append("<h2>Revokes not actioned</h2>")
        h.append(_table(["User", "Entitlement", "Reviewer", "Decided", "Still a member", "Issues"],
                        [f"<tr><td class='nw'><b>{e(r['item'].user)}</b></td><td class='sm'>{e(r['item'].group)}<br><span class='muted'>tier {r['tier']}</span></td>"
                         f"<td class='nw'>{e(r['item'].reviewer)}</td><td class='nw'>{_t(r['item'].decided)}</td>"
                         f"<td>{'<span class=critical>yes</span>' if r['still'] else 'no'}</td><td class='sm'>{_issues(r)}</td></tr>" for r in rec]))
    h.append("<h2>Entitlements by tier</h2>")
    h.append(_table(["Entitlement", "Tier", "Owner", "Members", "Every", "Last certified", "Status"],
                    [f"<tr><td><b>{e(r['entitlement'].group)}</b><br><span class='muted'>{e(r['entitlement'].application)}</span></td>"
                     f"<td class='num'>{r['entitlement'].tier}</td><td class='sm'>{e(r['entitlement'].owner)}</td><td class='num'>{r['members']}</td>"
                     f"<td class='num'>{str(r['every']) + ' d' if r['every'] else '–'}</td><td class='nw'>{_t(r['last'])}</td>"
                     f"<td>{_vpill(r['verdict'])}</td></tr>" for r in rv["entitlements"]]))
    h.append("<h2>All findings</h2>")
    h.append(_table(["Severity", "Area", "Subject", "Detail", "Next step", "Owner"],
                    [f"<tr><td>{_pill(f.severity, f.severity.upper())}</td><td class='nw'>{e(f.area)}</td><td>{e(f.subject)}</td>"
                     f"<td class='sm'>{e(f.detail)}</td><td class='fix'>{e(f.fix)}</td><td class='nw'>{e(f.owner)}</td></tr>" for f in findings]))
    h.append("<footer class='muted'>Generated by iamreview. Fictional demo data unless you ran it on your own exports. The monthly pack is "
             "access-review.md.</footer></main></body></html>")
    return "".join(h)


__all__ = ["render_html", "pack_md", "WARNING"]
