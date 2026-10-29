"""The checks: leavers who still have accounts, groups or roles; movers who kept the access of their previous department; joiners with access
before they start or without a manager; accounts nobody owns, duplicated, unused or with passwords that never expire; standing privileged
roles, privileged users without MFA or inactive, Tier 0 groups beyond the approved list, vaulted passwords not rotated and admin accounts
not vaulted; service accounts without an owner in employment or signing in interactively; guests without sponsor or inactive; and the
recertification campaign: items not reviewed, revokes not actioned, rubber-stamping and entitlements overdue for review by tier.
Each finding says what to do and who owns it."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .model import Account, Data, Person, _norm, days, key, split_list

CRITICAL, WARNING, INFO = "critical", "warning", "info"
ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
AREAS = ("Leavers", "Movers & joiners", "Accounts", "Privileged access", "Service & guest accounts", "Recertification")
VERDICT = {CRITICAL: "action needed", WARNING: "follow up", None: "clean"}


@dataclass
class Finding:
    severity: str
    area: str
    code: str
    subject: str
    detail: str
    fix: str
    owner: str = ""
    items: list[str] = field(default_factory=list)


@dataclass
class Issue:
    severity: str
    code: str
    text: str


def _n(k: int, word: str, plural: str | None = None) -> str:
    return f"{k} {word if k == 1 else (plural or word + 's')}"


def _top(items: list[str], k: int = 6) -> str:
    return ", ".join(items[:k]) + (f" and {len(items) - k} more" if len(items) > k else "")


def _d(v) -> str:
    return v.strftime("%d %b %Y") if v else "never"


def worst(issues: list[Issue]) -> str | None:
    sev = {i.severity for i in issues}
    return CRITICAL if CRITICAL in sev else WARNING if WARNING in sev else None


def _row(**kw) -> dict:
    kw.setdefault("issues", [])
    kw["severity"] = worst(kw["issues"])
    kw["verdict"] = VERDICT[kw["severity"]]
    return kw


def is_privileged(d: Data, a: Account) -> bool:
    return bool(d.tier0_groups_of(a) or d.roles_of(a))


def sensitive(d: Data, a: Account, max_tier: int = 1) -> list[str]:
    """Tier 0 groups, catalogue entitlements up to `max_tier` and directory roles held by the account."""
    out = [g for g in d.tier0_groups_of(a)]
    out += [e.group for e in d.catalogue_groups_of(a) if 0 < e.tier <= max_tier]
    out += [r.role + (" (eligible)" if r.eligible else "") for r in d.roles_of(a)]
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- leavers

def leavers(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    start = s.period_start or (today - timedelta(days=31))
    rows = []
    for p in d.people:
        if not p.left(today):
            continue
        accts = d.accounts_of(p)
        enabled = [a for a in accts if a.enabled]
        groups = {a.label: g for a in accts for g in [list(dict.fromkeys([e.group for e in d.catalogue_groups_of(a) if e.tier <= 2] + d.tier0_groups_of(a)))] if g}
        roles = [(a, r) for a in accts for r in d.roles_of(a)]
        in_period = p.end is not None and p.end >= start
        if not (in_period or enabled or groups or roles):
            continue
        end = p.end or today
        who = f"{p.name} ({p.employee_id})"
        due = end + timedelta(days=s.leaver_grace_days)
        after = [a for a in accts if a.last_logon and a.last_logon.date() > end]
        last = max((a.last_logon for a in accts if a.last_logon), default=None)
        priv = list(dict.fromkeys([g for a in accts for g in d.tier0_groups_of(a)] + [r.role for _, r in roles]))
        iss: list[Issue] = []
        if today > due:
            if enabled:
                txt = f"{who}: {_n(len(enabled), 'account')} still enabled {days(end, today)} days after the end date ({end:%d %b}): " + \
                      ", ".join(a.label + (f" in {', '.join(sensitive(d, a, 2))}" if sensitive(d, a, 2) else "") for a in enabled)
                if after:
                    txt += "; signed in after leaving: " + ", ".join(f"{a.label} on {a.last_logon:%d %b}" for a in after)
                iss.append(Issue(CRITICAL, "LVR-01", txt))
            if (groups or roles) and (priv or not enabled):
                gtxt = "; ".join(f"{n}: {_top(g, 4)}" for n, g in groups.items())
                rtxt = ", ".join(f"{r.role} ({'eligible' if r.eligible else 'active'})" for _, r in roles)
                iss.append(Issue(CRITICAL if priv else WARNING, "LVR-02",
                                 f"{who}: still holds " + "; ".join(x for x in (gtxt, ("roles: " + rtxt) if rtxt else "") if x)))
        elif enabled:
            iss.append(Issue(INFO, "LVR-01", f"{who}: left {end:%d %b}, inside the {s.leaver_grace_days}-day grace until {due:%d %b}"))
        rows.append(_row(person=p, accounts=accts, enabled=enabled, groups=sum(len(g) for g in groups.values()), roles=roles, priv=priv,
                         last=last, after=after, due=due, in_period=in_period, issues=iss))
    return sorted(rows, key=lambda r: (ORDER.get(r["severity"], 3), r["person"].end or today, r["person"].employee_id))


# ---------------------------------------------------------------- movers and joiners

def _dept_tags(e) -> set[str]:
    return {key(x) for x in split_list(e.department.replace(",", ";"))}


def movers(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    start = s.period_start or (today - timedelta(days=31))
    rows = []
    for p in d.people:
        if p.left(today) or not p.moved or p.moved > today:
            continue
        kept = []
        for a in d.accounts_of(p):
            for e in d.catalogue_groups_of(a):
                tags = _dept_tags(e)
                if not tags or key(p.department) in tags:
                    continue
                if p.previous_department and key(p.previous_department) not in tags:
                    continue
                kept.append((a, e))
        if not kept and p.moved < start:
            continue
        grace = p.moved + timedelta(days=s.mover_grace_days)
        iss = []
        if kept:
            ents = sorted({e.group: e for _, e in kept}.values(), key=lambda e: (e.tier, e.group))
            txt = f"{p.name} ({p.employee_id}): moved {p.previous_department or '?'} → {p.department} on {p.moved:%d %b} and still holds " + \
                  ", ".join(f"{e.group} ({e.application}, tier {e.tier})" for e in ents)
            if today > grace:
                iss.append(Issue(CRITICAL if min(e.tier for e in ents) <= 1 else WARNING, "MOV-01",
                                 txt + f"; {days(grace, today)} days past the {s.mover_grace_days}-day grace"))
            else:
                iss.append(Issue(INFO, "MOV-01", txt + f"; inside the grace until {grace:%d %b}"))
        rows.append(_row(person=p, kept=kept, grace=grace, issues=iss))
    return sorted(rows, key=lambda r: (ORDER.get(r["severity"], 3), r["person"].moved, r["person"].employee_id))


def joiners(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    rows = []
    for p in d.people:
        if p.left(today) or not p.start or p.start < today - timedelta(days=s.joiner_window_days):
            continue
        accts = d.accounts_of(p)
        early = []
        for a in accts:
            if d.linked_ad(a):
                continue
            if p.start > today and a.enabled:
                if a.last_logon:
                    early.append(f"{a.label} signed in on {a.last_logon:%d %b}")
                sens = sensitive(d, a, 2)
                if sens:
                    early.append(f"{a.label} already in {_top(sens, 4)}")
            for g in d.groups_of(a):
                ad = d.added.get((key(a.name), key(g)))
                if ad and ad < p.start:
                    early.append(f"{g} granted {ad:%d %b}")
        iss = []
        if early:
            iss.append(Issue(WARNING, "JNR-01", f"{p.name} ({p.employee_id}): starts {p.start:%d %b}; access before the start date: " + "; ".join(dict.fromkeys(early))))
        mgr = d.find_person(p.manager)
        if not p.manager:
            iss.append(Issue(WARNING, "JNR-02", f"{p.name} ({p.employee_id}): no manager in the HR record: nobody to approve or review the access"))
        elif not mgr or mgr.left(today):
            iss.append(Issue(WARNING, "JNR-02", f"{p.name} ({p.employee_id}): manager {p.manager} {'has left' if mgr else 'is not in the HR roster'}"))
        rows.append(_row(person=p, accounts=accts, manager=mgr, issues=iss))
    return sorted(rows, key=lambda r: (ORDER.get(r["severity"], 3), r["person"].start, r["person"].employee_id))


# ---------------------------------------------------------------- accounts

def account_rows(d: Data) -> list[dict]:
    """Orphans and duplicate employee IDs (orphans.csv), inactive accounts and passwords that never expire."""
    s, today = d.settings, d.today
    rows = []
    dup: dict[tuple[str, str], list[Account]] = defaultdict(list)
    for a in d.accounts():
        if not a.enabled or d.linked_ad(a):            # a synced Entra ID user is judged on its AD account
            continue
        kind = d.kind(a)
        p = d.person_of(a)
        iss = []
        if kind in ("standard", "admin") or (kind == "service" and not d.is_registered_service(a)):
            if not p:
                eid = d.employee_id_of(a)
                why = f"employee ID {eid} is not in the HR roster" if eid else "no employee ID"
                if kind == "service":
                    why += "; looks like a service account but is not in the register"
                sens = sensitive(d, a)
                iss.append(Issue(CRITICAL if sens else WARNING, "ACC-01", f"{a.label}: {why}" + (f"; holds {_top(sens, 4)}" if sens else "")))
        if kind == "standard" and d.employee_id_of(a):
            dup[(a.directory, key(d.employee_id_of(a)))].append(a)
        if kind in ("standard", "admin") and not (p and p.not_started(today)) and not (p and p.left(today)):
            last = d.last_activity(a)
            idle = days(last, today) if last else (days(a.created, today) if a.created else None)
            if idle is not None and idle > s.inactive_days:
                iss.append(Issue(WARNING, "ACC-03", f"{a.label}: " + (f"last sign-in {_d(last)}, {idle} days ago" if last else
                                                                     f"never signed in, created {_d(a.created)}")))
        if a.directory == "AD" and kind in ("standard", "admin") and a.pwd_never_expires:
            v = d.vaulted(a)
            if not (v and v.managed is not False):
                iss.append(Issue(WARNING, "ACC-04", f"{a.label}: password never expires" + (f", last set {_d(a.pwd_last_set)}" if a.pwd_last_set else "")))
        if iss:
            rows.append(_row(account=a, person=p, kind=kind, issues=iss))
    for (directory, eid), accts in sorted(dup.items()):
        if len(accts) > 1:
            names = ", ".join(a.name for a in accts)
            for a in accts:
                rows.append(_row(account=a, person=d.person_of(a), kind="standard",
                                 issues=[Issue(WARNING, "ACC-02", f"employee ID {accts[0].employee_id} on {len(accts)} {directory} accounts: {names}")]))
    for eid in sorted(set(d.hr_duplicates)):
        p = d.person_by_id[key(eid)]
        rows.append(_row(account=None, person=p, kind="hr", issues=[Issue(WARNING, "ACC-02", f"employee ID {eid} appears more than once in the HR roster")]))
    return rows


# ---------------------------------------------------------------- privileged access

def privileged_rows(d: Data) -> list[dict]:
    """One row per privileged holding: a directory role (active or eligible) or a Tier 0 group membership."""
    s, today = d.settings, d.today
    pim = {key(r) for r in s.pim_roles}
    crit = {key(r) for r in s.critical_roles}
    approved = {key(x) for x in s.approved_tier0}
    rows = []
    holders: dict[str, Account | str] = {}
    for r in sorted(d.roles, key=lambda r: (key(r.role), key(r.principal), r.state)):
        a = d.account(r.principal)
        bg = bool(a and d.is_break_glass(a)) or key(r.principal) in d.break_glass
        iss = []
        if r.standing and (key(r.role) in pim or not pim):
            span = f"until {r.end:%d %b %Y}" if r.end else "permanent"
            if bg:
                iss.append(Issue(INFO, "PRV-01", f"break-glass {r.principal}: standing {r.role} ({span}), expected"))
            else:
                iss.append(Issue(CRITICAL if key(r.role) in crit else WARNING, "PRV-01",
                                 f"{r.principal}: standing {r.role} ({span}, {r.member_type or 'direct'} assignment), not eligible through PIM"))
        rows.append(dict(source="Entra role", principal=r.principal, account=a, what=r.role,
                         how="eligible" if r.eligible else "activated" if r.activated else "active (standing)", role=r, break_glass=bg, issues=iss))
        holders.setdefault(key(r.principal), a or r.principal)
    for g in sorted({gr for a in d.accounts() for gr in d.tier0_groups_of(a)}, key=key):
        for m in sorted(d.members_of.get(key(g), []) or [], key=key):
            a = d.account(m)
            bg = bool(a and d.is_break_glass(a))
            iss = []
            if key(m) not in approved and not bg:
                iss.append(Issue(CRITICAL, "PRV-03", f"{m} is in {g} and not on the approved Tier 0 list"))
            rows.append(dict(source="AD group", principal=m, account=a, what=g, how="member", role=None, break_glass=bg, issues=iss))
            holders.setdefault(key(m), a or m)
    # per holder: MFA and activity
    for h, a in holders.items():
        if not isinstance(a, Account) or d.is_break_glass(a):
            continue
        mine = [r for r in rows if key(r["principal"]) == h]
        ent = a if a.directory == "Entra" else d.linked_entra(a)
        if ent and ent.mfa is False:
            mine[0]["issues"].append(Issue(CRITICAL, "PRV-02", f"{a.name}: privileged ({_top([r['what'] for r in mine], 3)}) and no MFA method registered"))
        last = d.last_activity(a)
        idle = days(last, today) if last else None
        if a.enabled and (idle is None or idle > s.privileged_inactive_days):
            mine[0]["issues"].append(Issue(WARNING, "PRV-02", f"{a.name}: privileged ({_top([r['what'] for r in mine], 3)}) and "
                                                              + (f"no sign-in for {idle} days" if last else "never signed in")))
    for r in rows:
        a = r["account"]
        p = d.person_of(a) if isinstance(a, Account) else None
        r.update(person=p, vaulted=bool(isinstance(a, Account) and d.vaulted(a)),
                 last=d.last_activity(a) if isinstance(a, Account) else None,
                 mfa=(a if a and a.directory == "Entra" else d.linked_entra(a) if a else None))
        r["mfa"] = r["mfa"].mfa if r["mfa"] else None
        r["severity"] = worst(r["issues"])
        r["verdict"] = VERDICT[r["severity"]]
    return rows


def pam_rows(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    rows = []
    for p in sorted(d.pam, key=lambda x: (key(x.safe), key(x.account))):
        rot = s.rotation_days(p.platform)
        age = days(p.last_change, today) if p.last_change else None
        iss = []
        if age is None or age > rot:
            iss.append(Issue(CRITICAL if age is None or age > 2 * rot else WARNING, "PAM-01",
                             f"{p.account} ({p.safe}, {p.platform}): " + (f"password last changed {_d(p.last_change)}, {age} days ago" if age is not None
                                                                         else "no password change recorded") + f" (policy {rot} days)"))
        if p.managed is False:
            iss.append(Issue(WARNING, "PAM-01", f"{p.account} ({p.safe}): automatic password management is off"))
        rows.append(_row(pam=p, age=age, rotation=rot, issues=iss))
    # admin, Tier 0 and break-glass accounts that are not in the vault
    need = {key(x) for x in s.vault_required}
    for a in d.accounts():
        if not a.enabled or d.linked_ad(a):
            continue
        why = []
        if "tier0" in need and d.tier0_groups_of(a):
            why.append("Tier 0: " + ", ".join(d.tier0_groups_of(a)))
        if "admin" in need and d.is_admin(a):
            why.append("admin account")
        if "break_glass" in need and d.is_break_glass(a):
            why.append("break-glass account")
        if why and not d.vaulted(a):
            rows.append(_row(pam=None, account=a, age=None, rotation=None,
                             issues=[Issue(CRITICAL if d.tier0_groups_of(a) else WARNING, "PAM-02", f"{a.label} not in the vault ({'; '.join(why)})")]))
    return rows


# ---------------------------------------------------------------- service and guest accounts

def service_rows(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    rows = []
    for x in sorted(d.service, key=lambda x: key(x.account)):
        a = d.account(x.account) or d.account(x.account.split("@")[0])
        ent = (a if a and a.directory == "Entra" else d.linked_entra(a)) if a else None
        owner = d.find_person(x.owner)
        ostat = "none" if not x.owner else "not in HR" if not owner else "left" if owner.left(today) else "active"
        inter = ent.last_interactive if ent else None
        recent = inter is not None and days(inter, today) <= s.inactive_days
        iss = []
        enabled = bool(a and a.enabled)
        if ostat == "none":
            iss.append(Issue(WARNING, "SVC-01", f"{x.account}: no owner in the register"))
        elif ostat == "left":
            iss.append(Issue(CRITICAL if enabled else WARNING, "SVC-01",
                             f"{x.account}: owner {owner.name} left on {_d(owner.end)}" + ("; account still enabled" if enabled else "")))
        elif ostat == "not in HR":
            iss.append(Issue(WARNING, "SVC-01", f"{x.account}: owner {x.owner} is not in the HR roster"))
        if recent and not x.interactive:
            iss.append(Issue(CRITICAL, "SVC-02", f"{x.account}: interactive sign-in on {inter:%d %b} although the register says not allowed"))
        elif x.interactive:
            iss.append(Issue(WARNING, "SVC-02", f"{x.account}: interactive sign-in allowed" + (f", last used interactively {inter:%d %b}" if recent else "")))
        rows.append(_row(svc=x, account=a, owner=owner, owner_status=ostat, interactive_last=inter, vaulted=bool(a and d.vaulted(a)),
                         found=a is not None, issues=iss))
    return rows


def guest_rows(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    rows = []
    for a in d.entra:
        if not a.guest or not a.enabled:
            continue
        iss = []
        last = a.last_logon
        idle = days(last, today) if last else (days(a.created, today) if a.created else None)
        if idle is not None and idle > s.guest_inactive_days:
            iss.append(Issue(WARNING, "GST-01", f"{a.name}: " + (f"last sign-in {_d(last)}, {idle} days ago" if last else f"never signed in since {_d(a.created)}")))
        if not a.sponsors:
            iss.append(Issue(WARNING, "GST-02", f"{a.name}: no sponsor"))
        rows.append(_row(account=a, idle=idle, issues=iss))
    return sorted(rows, key=lambda r: (ORDER.get(r["severity"], 3), key(r["account"].name)))


# ---------------------------------------------------------------- recertification

def recert_items(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    rows = []
    for i in d.recert:
        e = d.entitlement.get(key(i.group))
        tier = e.tier if e else 3
        still = d.is_member(i.user, i.group)
        iss = []
        if i.decision == "approve":
            status = "approved"
        elif i.decision == "revoke":
            if i.removed:
                lag = days(i.decided or i.removed, i.removed)
                status = f"revoked, removed in {lag} days"
                if lag is not None and lag > s.revoke_sla_days:
                    iss.append(Issue(INFO, "REC-02", f"{i.user} from {i.group}: removed {lag} days after the decision (SLA {s.revoke_sla_days})"))
            else:
                age = days(i.decided, today) if i.decided else None
                status = f"revoke pending {age} days" if age is not None else "revoke pending"
                if age is None or age > s.revoke_sla_days:
                    iss.append(Issue(CRITICAL if still else WARNING, "REC-02",
                                     f"{i.user} from {i.group}: revoked {_d(i.decided)} by {i.reviewer or '?'}, not removed after {age} days"
                                     + ("; still a member" if still else "; not recorded as removed")))
        elif i.due and i.due < today:
            status = "no decision, overdue"
            iss.append(Issue(CRITICAL if tier <= 1 else WARNING, "REC-01", f"{i.user} in {i.group} (tier {tier}): no decision by {i.reviewer or '?'}, due {i.due:%d %b}"))
        else:
            status = "open"
        rows.append(_row(item=i, tier=tier, application=e.application if e else "", still=still, status=status, rubber=False, issues=iss))
    return rows


def reviewers(d: Data, items: list[dict]) -> list[dict]:
    s = d.settings
    by = defaultdict(list)
    for r in items:
        by[(r["item"].campaign, r["item"].reviewer)].append(r)
    out = []
    for (camp, rev), rs in sorted(by.items()):
        dec = [r for r in rs if r["item"].decision]
        times = sorted(r["item"].decided for r in dec if r["item"].decided)
        ok = sum(r["item"].decision == "approve" for r in dec)
        span = (times[-1] - times[0]).total_seconds() / 60 if len(times) > 1 else None
        pct = 100 * ok / len(dec) if dec else None
        iss = []
        if len(dec) >= s.rubber_min_items and pct is not None and pct >= s.rubber_approve_pct and span is not None and span <= s.rubber_max_minutes:
            iss.append(Issue(WARNING, "REC-03", f"{rev}: approved {ok} of {len(dec)} items in {round(span)} min "
                                                f"({times[0]:%H:%M}–{times[-1]:%H:%M} on {times[0]:%d %b}), {camp}"))
            for r in dec:
                r["rubber"] = True
        out.append(_row(campaign=camp, reviewer=rev, items=len(rs), decided=len(dec), approved=ok, revoked=sum(r["item"].decision == "revoke" for r in dec),
                        pending=len(rs) - len(dec), first=times[0] if times else None, last=times[-1] if times else None, span=span, approve_pct=pct,
                        issues=iss))
    return out


def entitlement_rows(d: Data) -> list[dict]:
    s, today = d.settings, d.today
    last_dec: dict[str, datetime] = {}
    for i in d.recert:
        if i.decision and i.decided:
            k = key(i.group)
            last_dec[k] = max(last_dec.get(k, i.decided), i.decided)
    rows = []
    for e in sorted(d.catalogue, key=lambda e: (e.tier, key(e.group))):
        every = e.recert_days or s.recert_default_days
        members = len(d.members_of.get(key(e.group), []))
        cands = [x for x in (last_dec.get(key(e.group)), e.last_certified) if x]
        last = max((x.date() if isinstance(x, datetime) else x) for x in cands) if cands else None
        due = last + timedelta(days=every) if last and every else None
        iss = []
        if every and members:
            if not last or today > due:
                iss.append(Issue(CRITICAL if e.tier <= 1 else WARNING, "REC-04",
                                 f"{e.group} ({e.application}, tier {e.tier}, {members} members): " +
                                 (f"last certified {_d(last)}, {days(due, today)} days overdue (every {every} days)" if last else
                                  f"never certified (every {every} days)")))
        rows.append(_row(entitlement=e, every=every, members=members, last=last, due=due, issues=iss))
    return rows


# ---------------------------------------------------------------- everything

def review(d: Data) -> dict:
    items = recert_items(d)
    revs = reviewers(d, items)
    return dict(leavers=leavers(d), movers=movers(d), joiners=joiners(d), accounts=account_rows(d), privileged=privileged_rows(d),
                pam=pam_rows(d), service=service_rows(d), guests=guest_rows(d), recert=items, reviewers=revs, entitlements=entitlement_rows(d))


SECTIONS = {"Leavers": ("leavers",), "Movers & joiners": ("movers", "joiners"), "Accounts": ("accounts",),
            "Privileged access": ("privileged", "pam"), "Service & guest accounts": ("service", "guests"),
            "Recertification": ("recert", "reviewers", "entitlements")}
CODES = {  # code: (area, owner key, subject, next step)
    "LVR-01": ("Leavers", "leavers", "leavers with accounts still enabled after the grace",
               "Disable the accounts today (AD and Entra ID), revoke the sessions, and check what they did after the end date; find why the leaver "
               "ticket did not reach IAM (HR feed, late notice, manual step)."),
    "LVR-02": ("Leavers", "leavers", "leavers still in groups or holding roles",
               "Remove the group memberships and the role assignments or eligibilities of the leaver's accounts, and add the step to the leaver runbook."),
    "MOV-01": ("Movers & joiners", "movers", "movers who kept access of their previous department",
               "Ask the new manager to confirm or remove each entitlement; remove by default after the grace, and trigger a mover review from the "
               "HR movement date."),
    "JNR-01": ("Movers & joiners", "joiners", "joiners with access before their start date",
               "Keep pre-created accounts disabled until the start date and grant application access on day one; check who used the account."),
    "JNR-02": ("Movers & joiners", "joiners", "joiners without a manager in HR",
               "Ask HR to record the manager: without it nobody approves the access or reviews it."),
    "ACC-01": ("Accounts", "accounts", "enabled accounts with no HR record",
               "Find the owner: link the employee ID, register it as a service account, or disable it now and delete it after 30 days."),
    "ACC-02": ("Accounts", "accounts", "duplicate employee IDs",
               "Keep one standard account per person: merge or disable the extra one and correct the employee ID with HR."),
    "ACC-03": ("Accounts", "accounts", "enabled accounts inactive beyond the policy",
               "Confirm with the manager (long leave, seasonal) and disable the rest; consider an automatic disable at the threshold."),
    "ACC-04": ("Accounts", "accounts", "human accounts with a password that never expires",
               "Clear PasswordNeverExpires, or move the account to passwordless or the vault; it should only exist on vaulted accounts."),
    "PRV-01": ("Privileged access", "privileged", "standing privileged role assignments outside PIM",
               "Convert to eligible assignments in PIM with approval and MFA on activation; keep standing only on the break-glass accounts."),
    "PRV-02": ("Privileged access", "privileged", "privileged accounts without MFA or inactive",
               "Require MFA registration before any privileged role (Conditional Access on the role), and remove eligibilities not used in the period."),
    "PRV-03": ("Privileged access", "privileged", "Tier 0 group members not on the approved list",
               "Remove the member or record the approval; Tier 0 membership should be a short, named list reviewed every month."),
    "PAM-01": ("Privileged access", "pam", "vaulted passwords not rotated within policy",
               "Rotate now from the vault, fix the CPM / platform error that stopped it, and turn automatic management back on."),
    "PAM-02": ("Privileged access", "pam", "privileged accounts not in the vault",
               "Onboard the account to the vault with automatic rotation, or remove the privilege."),
    "SVC-01": ("Service & guest accounts", "service", "service accounts without an owner in employment",
               "Name a new owner (a person in employment) in the register; if nobody claims it, disable it and watch what breaks in a change window."),
    "SVC-02": ("Service & guest accounts", "service", "service accounts with interactive sign-in",
               "Block interactive sign-in (Deny log on locally / through RDP in AD, Conditional Access for Entra ID) and use a managed identity or "
               "gMSA where possible."),
    "GST-01": ("Service & guest accounts", "guests", "guests inactive beyond the policy",
               "Ask the sponsor and remove the guests nobody needs; an access review on guests every quarter keeps it small."),
    "GST-02": ("Service & guest accounts", "guests", "guests without a sponsor",
               "Assign a sponsor (the person who invited them or the business owner) or remove the guest."),
    "REC-01": ("Recertification", "recert", "recertification items not reviewed by the due date",
               "Chase the reviewers, escalate to their manager, and decide the default: revoke on no decision for tier 0 and 1."),
    "REC-02": ("Recertification", "recert", "revoke decisions not actioned within the SLA",
               "Remove the access now and close the loop: every revoke needs a removal date as evidence for the auditor."),
    "REC-03": ("Recertification", "recert", "reviewers approving everything in minutes",
               "Talk to the reviewer, re-open their items, and show last sign-in and department next to each item in the next campaign."),
    "REC-04": ("Recertification", "recert", "entitlements overdue for recertification",
               "Include them in the next campaign and schedule the frequency of each tier in the calendar."),
}


def run_all(d: Data, rv: dict | None = None) -> list[Finding]:
    rv = rv if rv is not None else review(d)
    s = d.settings
    out: list[Finding] = []
    hits = defaultdict(list)
    for name in ("leavers", "movers", "joiners", "accounts", "privileged", "pam", "service", "guests", "recert", "reviewers", "entitlements"):
        for r in rv[name]:
            for i in r["issues"]:
                hits[i.code].append(i)
    for code, (area, owner, subject, fix) in CODES.items():
        for sev in (CRITICAL, WARNING, INFO):
            xs = list({i.text: i for i in hits.get(code, []) if i.severity == sev}.values())
            if not xs:
                continue
            word = "item" if code in ("REC-01", "REC-02") else "entitlement" if code == "REC-04" else "finding"
            detail = _top([i.text for i in xs], 8)
            if code == "REC-01":                  # one line per reviewer and entitlement instead of one per item
                by = defaultdict(list)
                for r in rv["recert"]:
                    if any(i.code == code and i.severity == sev for i in r["issues"]):
                        by[(r["item"].reviewer or "?", r["item"].group, r["tier"])].append(r["item"].user)
                detail = "; ".join(f"{rev}: {_n(len(us), 'item')} in {g} (tier {t}) without a decision" for (rev, g, t), us in sorted(by.items()))
            subj = f"{_n(len(xs), word)}: {subject}" if sev != INFO else f"{_n(len(xs), word)} for information ({code})"
            out.append(Finding(sev, area, code, subj, detail,
                               fix if sev != INFO else "No action unless it changes before the next review.", s.owner(owner),
                               [i.text.split(":")[0] for i in xs]))
    # information: the population and the campaign
    sm = summary(d, rv)
    out.append(Finding(INFO, "Accounts", "MET-01", f"{sm['people']} people in HR, {sm['accounts']} accounts reviewed",
                       f"{sm['active']} active; {_n(sm['leavers_period'], 'leaver')}, {_n(sm['movers_period'], 'mover')} and {_n(sm['joiners'], 'joiner')} in the period; "
                       f"{sm['ad']} AD and {sm['entra']} Entra ID accounts ({sm['guests']} guests, {sm['services']} service accounts registered)",
                       "Track the trend month by month.", s.owner("accounts")))
    if rv["recert"]:
        out.append(Finding(INFO, "Recertification", "MET-02", f"Campaign completion {sm['recert_done']:.0f}%",
                           f"{sm['recert_items']} items, {sm['recert_decided']} decided, {sm['recert_revoked']} revoked, "
                           f"{sm['recert_removed']} removals recorded", "Report it in the IAM service review.", s.owner("recert")))
    out.sort(key=lambda f: (ORDER[f.severity], AREAS.index(f.area), f.code))
    return out


def summary(d: Data, rv: dict) -> dict:
    today = d.today
    start = d.settings.period_start or (today - timedelta(days=31))
    codes = lambda name, c: sum(any(i.code == c and i.severity != INFO for i in r["issues"]) for r in rv[name])  # noqa: E731
    items = rv["recert"]
    dec = [r for r in items if r["item"].decision]
    return dict(
        people=len(d.people), active=sum(not p.left(today) and not p.not_started(today) for p in d.people),
        accounts=len(d.ad) + len(d.entra), ad=len(d.ad), entra=len(d.entra), guests=sum(a.guest for a in d.entra), services=len(d.service),
        leavers_period=sum(r["in_period"] for r in rv["leavers"]), leavers_access=codes("leavers", "LVR-01"),
        leavers_groups=codes("leavers", "LVR-02"),
        movers_period=sum(1 for r in rv["movers"] if r["person"].moved >= start), movers_kept=codes("movers", "MOV-01"),
        joiners=len(rv["joiners"]), joiners_issues=sum(1 for r in rv["joiners"] if r["severity"]),
        orphans=sum(1 for r in rv["accounts"] if any(i.code == "ACC-01" for i in r["issues"])),
        duplicates=sum(1 for r in rv["accounts"] if any(i.code == "ACC-02" for i in r["issues"])),
        inactive=sum(1 for r in rv["accounts"] if any(i.code == "ACC-03" for i in r["issues"])),
        pwd_never=sum(1 for r in rv["accounts"] if any(i.code == "ACC-04" for i in r["issues"])),
        standing=sum(1 for r in rv["privileged"] for i in r["issues"] if i.code == "PRV-01" and i.severity != INFO),
        priv_holders=len({key(r["principal"]) for r in rv["privileged"]}),
        tier0_unapproved=sum(1 for r in rv["privileged"] for i in r["issues"] if i.code == "PRV-03"),
        no_mfa=sum(1 for r in rv["privileged"] for i in r["issues"] if i.code == "PRV-02" and i.severity == CRITICAL),
        pam_overdue=sum(1 for r in rv["pam"] for i in r["issues"] if i.code == "PAM-01" and "automatic" not in i.text),
        not_vaulted=sum(1 for r in rv["pam"] for i in r["issues"] if i.code == "PAM-02"),
        svc_issues=sum(1 for r in rv["service"] if r["severity"]), guest_issues=sum(1 for r in rv["guests"] if r["severity"]),
        recert_items=len(items), recert_decided=len(dec), recert_done=100 * len(dec) / len(items) if items else 0.0,
        recert_overdue=sum(1 for r in items if any(i.code == "REC-01" for i in r["issues"])),
        recert_revoked=sum(r["item"].decision == "revoke" for r in items),
        recert_removed=sum(1 for r in items if r["item"].decision == "revoke" and r["item"].removed),
        revoke_pending=sum(1 for r in items if any(i.code == "REC-02" and i.severity != INFO for i in r["issues"])),
        rubber=sum(1 for r in rv["reviewers"] if r["issues"]), rubber_items=sum(r["decided"] for r in rv["reviewers"] if r["issues"]),
        ent_overdue=sum(1 for r in rv["entitlements"] if r["issues"]),
    )


def area_status(findings: list[Finding]) -> dict[str, str]:
    st = {}
    for a in AREAS:
        sev = [f.severity for f in findings if f.area == a and f.severity != INFO]
        st[a] = CRITICAL if CRITICAL in sev else WARNING if sev else "ok"
    return st


def overall(findings: list[Finding]) -> str:
    st = set(area_status(findings).values())
    return VERDICT[CRITICAL] if CRITICAL in st else VERDICT[WARNING] if WARNING in st else VERDICT[None]


def now_label(when: datetime) -> str:
    return f"{when:%a %d %b %Y %H:%M}"


def person_label(p: Person | None) -> str:
    return f"{p.name} ({p.employee_id})" if p else "–"


__all__ = ["AREAS", "CRITICAL", "WARNING", "INFO", "Finding", "Issue", "review", "run_all", "summary", "area_status", "overall", "_norm"]
