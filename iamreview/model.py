"""Loading: the HR roster, the Active Directory and Entra ID user exports, group memberships, the entitlement catalogue, privileged roles,
the PAM vault, the service account register, the recertification campaign results and settings.json, with forgiving column names
(PowerShell, Microsoft Graph and common HR / PAM export names included), into plain dataclasses, and the links between them: every
account to a person through the employee ID, and every synced Entra ID user to its Active Directory account."""
from __future__ import annotations

import csv
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

HR_ALIASES = {
    "employee_id": ["employee id", "employeeid", "employee number", "emp id", "worker id", "personnel number", "id", "numero empleado"],
    "name": ["name", "full name", "display name", "displayname", "employee name", "nombre"],
    "department": ["department", "dept", "business unit", "departamento"],
    "manager": ["manager", "manager id", "line manager", "manager employee id", "reports to", "responsable"],
    "status": ["status", "employment status", "worker status", "estado"],
    "start": ["start date", "hire date", "start", "joining date", "fecha alta", "fecha inicio"],
    "end": ["end date", "termination date", "leaving date", "last day", "leave date", "fecha baja", "fecha fin"],
    "moved": ["last movement date", "movement date", "transfer date", "last transfer", "fecha movimiento"],
    "previous_department": ["previous department", "from department", "old department", "prior department", "departamento anterior"],
    "cost_centre": ["cost centre", "cost center", "costcenter", "centro coste", "centro de coste"],
    "location": ["location", "office", "site", "ubicacion", "sede"],
}
AD_ALIASES = {
    "sam": ["samaccountname", "sam account name", "sam", "logon name", "username", "account"],
    "employee_id": ["employeeid", "employee id", "employee number", "employeenumber"],
    "enabled": ["enabled", "account enabled", "habilitada"],
    "last_logon": ["lastlogondate", "lastlogontimestamp", "last logon", "last logon timestamp", "ultimo inicio"],
    "pwd_last_set": ["passwordlastset", "pwdlastset", "password last set"],
    "pwd_never": ["passwordneverexpires", "password never expires", "pwd never expires"],
    "created": ["whencreated", "when created", "created", "creado"],
    "member_of": ["memberof", "member of", "groups", "grupos"],
    "description": ["description", "descripcion"],
    "upn": ["userprincipalname", "upn"],
    "name": ["name", "displayname", "display name", "nombre"],
}
ENTRA_ALIASES = {
    "upn": ["userprincipalname", "user principal name", "upn"],
    "employee_id": ["employeeid", "employee id"],
    "enabled": ["accountenabled", "account enabled", "enabled"],
    "user_type": ["usertype", "user type", "tipo"],
    "created": ["createddatetime", "created date time", "created", "creado"],
    "last_signin": ["lastsignindatetime", "signinactivity lastsignindatetime", "last sign in", "last interactive sign in"],
    "last_success": ["lastsuccessfulsignindatetime", "signinactivity lastsuccessfulsignindatetime", "last successful sign in"],
    "last_noninteractive": ["lastnoninteractivesignindatetime", "signinactivity lastnoninteractivesignindatetime", "last non interactive sign in"],
    "sam": ["onpremisessamaccountname", "on premises sam account name", "samaccountname"],
    "sponsors": ["sponsors", "sponsor", "patrocinador"],
    "mfa": ["ismfaregistered", "mfa registered", "mfa", "mfa capable", "ismfacapable"],
    "name": ["displayname", "display name", "name", "nombre"],
}
MEMBER_ALIASES = {
    "group": ["group", "group name", "groupname", "entitlement", "grupo"],
    "member": ["member", "samaccountname", "userprincipalname", "user", "account", "principal", "miembro"],
    "source": ["source", "directory", "origen"],
    "added": ["added", "added on", "granted", "granted on", "fecha alta"],
}
CATALOGUE_ALIASES = {
    "group": ["group", "group name", "entitlement", "grupo"],
    "application": ["application", "app", "system", "aplicacion"],
    "tier": ["tier", "sensitivity tier", "sensitivity", "criticality", "nivel"],
    "owner": ["owner", "entitlement owner", "approver", "responsable"],
    "department": ["department", "department tag", "dept", "departamento"],
    "recert_days": ["recert days", "recertification days", "requires recertification every n days", "review every days", "recert every",
                    "recertify every days"],
    "privileged": ["privileged", "admin", "privilegiado"],
    "last_certified": ["last certified", "last recertified", "last review", "ultima revision"],
}
ROLE_ALIASES = {
    "principal": ["principal", "userprincipalname", "upn", "user", "member", "account"],
    "role": ["role", "role name", "roledefinition", "role definition", "rol"],
    "state": ["state", "assignment", "assignment state", "status", "estado"],
    "assignment_type": ["assignmenttype", "assignment type", "type", "tipo"],
    "start": ["startdatetime", "start date time", "start", "inicio"],
    "end": ["enddatetime", "end date time", "end", "expires", "fin"],
    "member_type": ["membertype", "member type"],
    "scope": ["directoryscopeid", "directory scope id", "scope", "ambito"],
}
PAM_ALIASES = {
    "account": ["account", "username", "user name", "account name", "cuenta"],
    "safe": ["safe", "safename", "safe name"],
    "platform": ["platform", "platformid", "platform id", "plataforma"],
    "address": ["address", "domain", "target", "host"],
    "last_change": ["last password change", "lastmodifiedtime", "last modified", "password last changed", "last changed", "ultimo cambio"],
    "last_used": ["last used", "lastusedtime", "last accessed", "last retrieved", "ultimo uso"],
    "owner": ["owner", "responsable"],
    "managed": ["automatic management", "automaticmanagementenabled", "managed", "cpm managed", "rotation enabled", "gestionada"],
}
SERVICE_ALIASES = {
    "account": ["account", "samaccountname", "userprincipalname", "service account", "name", "cuenta"],
    "owner": ["owner", "owner employee id", "business owner", "responsable"],
    "purpose": ["purpose", "description", "use", "uso", "proposito"],
    "interactive": ["interactive sign in allowed", "interactive allowed", "interactive", "interactive logon", "interactivo"],
    "directory": ["directory", "source", "origen"],
}
RECERT_ALIASES = {
    "campaign": ["campaign", "review", "campana"],
    "item": ["item id", "item", "id"],
    "group": ["group", "entitlement", "access", "resource", "grupo"],
    "user": ["user", "member", "account", "identity", "principal", "usuario"],
    "reviewer": ["reviewer", "reviewed by", "decided by", "revisor"],
    "decision": ["decision", "result", "outcome", "decision result", "resultado"],
    "decided": ["decided on", "decision date", "reviewed date", "reviewed on", "decided", "fecha decision"],
    "due": ["due date", "due", "campaign end", "end date", "fecha limite"],
    "removed": ["removed on", "removed", "remediated", "remediation date", "fulfilled", "fecha retirada"],
}
YES = {"yes", "y", "true", "1", "si", "x", "enabled", "registered", "allowed", "on"}
LEAVER_WORDS = {"leaver", "left", "terminated", "termination", "withdrawn", "inactive", "baja", "former", "exited"}
APPROVE_WORDS = {"approve", "approved", "keep", "certify", "certified", "maintain", "aprobar", "aprobado", "mantener"}
REVOKE_WORDS = {"revoke", "revoked", "remove", "removed", "deny", "denied", "revocar", "revocado", "retirar"}
DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M", "%d/%m/%Y", "%m/%d/%Y %I:%M:%S %p", "%d %b %Y %H:%M", "%d %b %Y")
FILETIME_EPOCH = datetime(1601, 1, 1)


def _norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", "".join(ch for ch in s if not unicodedata.combining(ch))).strip()


def key(v) -> str:
    """Matching key for account names, UPNs, groups and employee IDs: case and surrounding spaces ignored."""
    return str(v or "").strip().lower()


def parse_dt(v) -> datetime | None:
    s = str(v or "").strip()
    if not s or _norm(s) in {"never", "n a", "na", "none", "null", "0"}:
        return None
    if re.fullmatch(r"\d{15,19}", s):                         # raw lastLogonTimestamp / pwdLastSet (FILETIME, 100 ns since 1601)
        n = int(s)
        return None if n <= 0 or n >= 2**63 - 1 else FILETIME_EPOCH + timedelta(microseconds=n // 10)
    if re.fullmatch(r"\d{10}", s):                             # Unix time in seconds (PAM REST APIs)
        return datetime(1970, 1, 1) + timedelta(seconds=int(s))
    s = re.sub(r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})$", "", s)      # ISO with offset: kept as written (Graph returns UTC)
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def parse_date(v) -> date | None:
    d = parse_dt(v)
    return d.date() if d else None


def yes(v) -> bool:
    return _norm(v) in YES


def tri(v) -> bool | None:
    """yes / no / unknown (empty)."""
    return None if not str(v or "").strip() else yes(v)


def tier_of(v) -> int:
    n = _norm(v)
    m = re.search(r"\d", n)
    if m:
        return int(m.group(0))
    for words, t in ((("control plane", "critical", "privileged", "critica"), 0), (("high", "restricted", "confidential", "alta"), 1),
                     (("medium", "internal", "media"), 2), (("low", "public", "baja"), 3)):
        if any(w in n for w in words):
            return t
    return 3


def decision_of(v) -> str:
    n = _norm(v).split()
    if any(w in APPROVE_WORDS for w in n):
        return "approve"
    if any(w in REVOKE_WORDS for w in n):
        return "revoke"
    return ""


def split_list(v) -> list[str]:
    return [x.strip() for x in re.split(r"[;|\n]+", str(v or "")) if x.strip()]


def cn_of(v: str) -> str:
    """'CN=Domain Admins,CN=Users,DC=corp,DC=example' -> 'Domain Admins'; plain names are kept."""
    m = re.match(r"^\s*CN=((?:\\,|[^,])+)", v, re.I)
    return m.group(1).replace("\\,", ",").strip() if m else v.strip()


def _read(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = fh.readline()
        fh.seek(0)
        delim = max(",;\t", key=header.count)          # the header decides: values (DNs, lists) often contain commas or semicolons
        reader = csv.DictReader(fh, delimiter=delim)
        return list(reader.fieldnames or []), list(reader)


def _rows(path: Path, aliases: dict[str, list[str]]) -> list[dict]:
    fields, raw = _read(path)
    heads = {_norm(h): h for h in fields}
    cols = {}
    for k, names in aliases.items():
        for n in [k.replace("_", " ")] + names:
            if _norm(n) in heads and heads[_norm(n)] not in cols.values():
                cols[k] = heads[_norm(n)]
                break
    return [{k: (r.get(c) or "").strip() for k, c in cols.items()} for r in raw]


# ---------------------------------------------------------------- records

@dataclass
class Person:
    employee_id: str
    name: str = ""
    department: str = ""
    manager: str = ""
    status: str = ""
    start: date | None = None
    end: date | None = None
    moved: date | None = None
    previous_department: str = ""
    cost_centre: str = ""
    location: str = ""

    def left(self, today: date) -> bool:
        return (self.end is not None and self.end <= today) or any(w in _norm(self.status).split() for w in LEAVER_WORDS)

    def not_started(self, today: date) -> bool:
        return self.start is not None and self.start > today


@dataclass
class Account:
    directory: str                 # "AD" or "Entra"
    name: str                      # sAMAccountName or UPN
    employee_id: str = ""
    enabled: bool = True
    last_logon: datetime | None = None          # AD lastLogonTimestamp, or Entra last successful / any sign-in
    last_interactive: datetime | None = None    # Entra lastSignInDateTime (interactive)
    created: datetime | None = None
    pwd_last_set: datetime | None = None
    pwd_never_expires: bool = False
    member_of: list[str] = field(default_factory=list)
    description: str = ""
    upn: str = ""
    display_name: str = ""
    user_type: str = "Member"
    sam: str = ""                  # Entra: onPremisesSamAccountName (synced from AD)
    sponsors: list[str] = field(default_factory=list)
    mfa: bool | None = None

    @property
    def guest(self) -> bool:
        return _norm(self.user_type) == "guest"

    @property
    def label(self) -> str:
        return f"{self.name} ({self.directory})"


@dataclass
class Membership:
    group: str
    member: str
    source: str = ""
    added: date | None = None


@dataclass
class Entitlement:
    group: str
    application: str = ""
    tier: int = 3
    owner: str = ""
    department: str = ""
    recert_days: int = 0
    privileged: bool = False
    last_certified: date | None = None


@dataclass
class RoleAssignment:
    principal: str
    role: str
    state: str = "Active"          # Active or Eligible
    assignment_type: str = ""      # Assigned or Activated (active instances)
    start: datetime | None = None
    end: datetime | None = None
    member_type: str = ""
    scope: str = "/"

    @property
    def eligible(self) -> bool:
        return _norm(self.state).startswith("elig")

    @property
    def activated(self) -> bool:
        return _norm(self.assignment_type).startswith("activ")

    @property
    def standing(self) -> bool:
        """Active and not a just-in-time activation: assigned directly or through PIM as an active assignment."""
        return not self.eligible and not self.activated


@dataclass
class PamAccount:
    account: str
    safe: str = ""
    platform: str = ""
    address: str = ""
    last_change: datetime | None = None
    last_used: datetime | None = None
    owner: str = ""
    managed: bool | None = None


@dataclass
class ServiceAccount:
    account: str
    owner: str = ""
    purpose: str = ""
    interactive: bool = False
    directory: str = ""


@dataclass
class RecertItem:
    campaign: str
    item: str
    group: str
    user: str
    reviewer: str = ""
    decision: str = ""             # approve, revoke or "" (no decision)
    decided: datetime | None = None
    due: date | None = None
    removed: datetime | None = None


DEFAULT_OWNERS = {"leavers": "IAM operations lead", "movers": "IAM operations lead", "joiners": "HR operations", "accounts": "IAM operations lead",
                  "privileged": "Head of infrastructure", "pam": "PAM administrator", "service": "IAM operations lead",
                  "guests": "IAM operations lead", "recert": "IAM service owner"}
DEFAULT_PIM_ROLES = ["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator", "Security Administrator",
                     "Exchange Administrator", "SharePoint Administrator", "User Administrator", "Conditional Access Administrator",
                     "Application Administrator", "Cloud Application Administrator", "Intune Administrator", "Authentication Administrator"]


@dataclass
class Settings:
    organisation: str = "IT operations"
    as_of: datetime | None = None
    period_start: date | None = None
    leaver_grace_days: int = 1
    mover_grace_days: int = 14
    joiner_window_days: int = 30
    inactive_days: int = 90
    guest_inactive_days: int = 90
    privileged_inactive_days: int = 45
    pim_roles: list = field(default_factory=lambda: list(DEFAULT_PIM_ROLES))
    critical_roles: list = field(default_factory=lambda: ["Global Administrator", "Privileged Role Administrator",
                                                          "Privileged Authentication Administrator"])
    break_glass: list = field(default_factory=list)
    tier0_groups: list = field(default_factory=lambda: ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                                                        "Account Operators", "Backup Operators", "Server Operators", "Print Operators"])
    approved_tier0: list = field(default_factory=list)
    admin_account_pattern: str = r"^(adm|admin)[-_.]"
    service_account_pattern: str = r"^(svc|sa)[-_.]"
    pam_rotation_days: int = 90
    pam_rotation_by_platform: dict = field(default_factory=dict)
    vault_required: list = field(default_factory=lambda: ["tier0", "admin", "break_glass"])
    recert_default_days: int = 0
    revoke_sla_days: int = 5
    rubber_min_items: int = 50
    rubber_max_minutes: int = 10
    rubber_approve_pct: int = 100
    owners: dict = field(default_factory=lambda: dict(DEFAULT_OWNERS))

    def owner(self, k: str) -> str:
        return self.owners.get(k, "")

    def rotation_days(self, platform: str) -> int:
        for k, v in self.pam_rotation_by_platform.items():
            if key(k) == key(platform):
                return int(v)
        return self.pam_rotation_days


def settings_from_dict(raw: dict) -> Settings:
    s = Settings()
    for k, v in raw.items():
        if not hasattr(s, k):
            continue
        cur = getattr(s, k)
        if k == "as_of":
            v = parse_dt(v)
        elif k == "period_start":
            v = parse_date(v)
        elif k == "owners":
            v = {**cur, **v}
        elif isinstance(cur, bool):
            v = bool(v)
        elif isinstance(cur, int):
            v = int(v)
        setattr(s, k, v)
    return s


# ---------------------------------------------------------------- loaders

def load_hr(path: Path) -> list[Person]:
    out = [Person(r["employee_id"], r.get("name", ""), r.get("department", ""), r.get("manager", ""), r.get("status", ""),
                  parse_date(r.get("start")), parse_date(r.get("end")), parse_date(r.get("moved")), r.get("previous_department", ""),
                  r.get("cost_centre", ""), r.get("location", ""))
           for r in _rows(path, HR_ALIASES) if r.get("employee_id")]
    return sorted(out, key=lambda p: key(p.employee_id))


def load_ad(path: Path) -> list[Account]:
    out = []
    for r in _rows(path, AD_ALIASES):
        if not r.get("sam"):
            continue
        out.append(Account("AD", r["sam"], r.get("employee_id", ""), yes(r.get("enabled")) if r.get("enabled") else True,
                           parse_dt(r.get("last_logon")), None, parse_dt(r.get("created")), parse_dt(r.get("pwd_last_set")),
                           yes(r.get("pwd_never")), [cn_of(x) for x in split_list(r.get("member_of"))], r.get("description", ""),
                           r.get("upn", ""), r.get("name", "")))
    return sorted(out, key=lambda a: key(a.name))


def load_entra(path: Path) -> list[Account]:
    out = []
    for r in _rows(path, ENTRA_ALIASES):
        if not r.get("upn"):
            continue
        times = [t for t in (parse_dt(r.get("last_signin")), parse_dt(r.get("last_success")), parse_dt(r.get("last_noninteractive"))) if t]
        out.append(Account("Entra", r["upn"], r.get("employee_id", ""), yes(r.get("enabled")) if r.get("enabled") else True,
                           max(times) if times else None, parse_dt(r.get("last_signin")), parse_dt(r.get("created")), upn=r["upn"],
                           display_name=r.get("name", ""), user_type=r.get("user_type") or "Member", sam=r.get("sam", ""),
                           sponsors=split_list(r.get("sponsors")), mfa=tri(r.get("mfa"))))
    return sorted(out, key=lambda a: key(a.name))


def load_memberships(path: Path) -> list[Membership]:
    return [Membership(cn_of(r["group"]), r["member"], r.get("source", ""), parse_date(r.get("added")))
            for r in _rows(path, MEMBER_ALIASES) if r.get("group") and r.get("member")]


def load_catalogue(path: Path) -> list[Entitlement]:
    out = []
    for r in _rows(path, CATALOGUE_ALIASES):
        if not r.get("group"):
            continue
        days = re.search(r"\d+", r.get("recert_days", ""))
        t = tier_of(r.get("tier"))
        out.append(Entitlement(r["group"], r.get("application", ""), t, r.get("owner", ""), r.get("department", ""),
                               int(days.group(0)) if days else 0, yes(r.get("privileged")) or t == 0, parse_date(r.get("last_certified"))))
    return out


def load_roles(path: Path) -> list[RoleAssignment]:
    return [RoleAssignment(r["principal"], r["role"], r.get("state") or "Active", r.get("assignment_type", ""), parse_dt(r.get("start")),
                           parse_dt(r.get("end")), r.get("member_type", ""), r.get("scope") or "/")
            for r in _rows(path, ROLE_ALIASES) if r.get("principal") and r.get("role")]


def load_pam(path: Path) -> list[PamAccount]:
    return [PamAccount(r["account"], r.get("safe", ""), r.get("platform", ""), r.get("address", ""), parse_dt(r.get("last_change")),
                       parse_dt(r.get("last_used")), r.get("owner", ""), tri(r.get("managed")))
            for r in _rows(path, PAM_ALIASES) if r.get("account")]


def load_service(path: Path) -> list[ServiceAccount]:
    return [ServiceAccount(r["account"], r.get("owner", ""), r.get("purpose", ""), yes(r.get("interactive")), r.get("directory", ""))
            for r in _rows(path, SERVICE_ALIASES) if r.get("account")]


def load_recert(path: Path) -> list[RecertItem]:
    out = [RecertItem(r.get("campaign", ""), r.get("item") or f"I{k + 1:04d}", r.get("group", ""), r.get("user", ""), r.get("reviewer", ""),
                      decision_of(r.get("decision")), parse_dt(r.get("decided")), parse_date(r.get("due")), parse_dt(r.get("removed")))
           for k, r in enumerate(_rows(path, RECERT_ALIASES)) if r.get("group") and r.get("user")]
    return sorted(out, key=lambda i: (i.campaign, i.item))


# ---------------------------------------------------------------- the joined view

@dataclass
class Data:
    settings: Settings
    as_of: datetime
    people: list[Person]
    ad: list[Account] = field(default_factory=list)
    entra: list[Account] = field(default_factory=list)
    memberships: list[Membership] = field(default_factory=list)
    catalogue: list[Entitlement] = field(default_factory=list)
    roles: list[RoleAssignment] = field(default_factory=list)
    pam: list[PamAccount] = field(default_factory=list)
    service: list[ServiceAccount] = field(default_factory=list)
    recert: list[RecertItem] = field(default_factory=list)
    sources: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.index()

    def index(self) -> None:
        """Build the lookups. Call again after changing the lists."""
        s = self.settings
        self.person_by_id: dict[str, Person] = {}
        self.hr_duplicates: list[str] = []
        for p in self.people:
            if key(p.employee_id) in self.person_by_id:
                self.hr_duplicates.append(p.employee_id)
            self.person_by_id.setdefault(key(p.employee_id), p)
        self.ad_by_name = {key(a.name): a for a in self.ad}
        self.entra_by_name = {key(a.name): a for a in self.entra}
        self.ad_by_upn = {key(a.upn): a for a in self.ad if a.upn}
        self.entra_by_sam = {key(a.sam): a for a in self.entra if a.sam}
        self.entitlement = {key(e.group): e for e in self.catalogue}
        self.tier0 = {key(g) for g in s.tier0_groups} | {key(e.group) for e in self.catalogue if e.tier == 0}
        self.service_by_name = {key(x.account): x for x in self.service}
        self.pam_by_name: dict[str, PamAccount] = {}
        for p in self.pam:
            for n in {key(p.account), key(p.account.split("@")[0]), key(p.account.split("\\")[-1])}:
                self.pam_by_name.setdefault(n, p)
        self.break_glass = {key(x) for x in s.break_glass}
        self._admin = re.compile(s.admin_account_pattern, re.I) if s.admin_account_pattern else None
        self._svc = re.compile(s.service_account_pattern, re.I) if s.service_account_pattern else None
        groups: dict[str, set[str]] = {}
        added: dict[tuple[str, str], date] = {}
        for m in self.memberships:
            groups.setdefault(key(m.member), set()).add(m.group)
            if m.added:
                added[(key(m.member), key(m.group))] = m.added
        for a in self.ad:                           # memberOf from the AD export adds what the membership file does not list
            for g in a.member_of:
                groups.setdefault(key(a.name), set()).add(g)
        self._groups = groups
        self.added = added
        self.members_of: dict[str, list[str]] = {}
        for member, gs in groups.items():
            for g in gs:
                self.members_of.setdefault(key(g), []).append(member)

    @property
    def today(self) -> date:
        return self.as_of.date()

    # -------- accounts
    def accounts(self) -> list[Account]:
        return self.ad + self.entra

    def account(self, name: str) -> Account | None:
        k = key(name)
        return self.ad_by_name.get(k) or self.entra_by_name.get(k) or self.ad_by_upn.get(k)

    def linked_ad(self, a: Account) -> Account | None:
        """The AD account of a synced Entra ID user."""
        return self.ad_by_name.get(key(a.sam)) if a.directory == "Entra" and a.sam else None

    def linked_entra(self, a: Account) -> Account | None:
        return self.entra_by_sam.get(key(a.name)) if a.directory == "AD" else None

    def employee_id_of(self, a: Account) -> str:
        if a.employee_id:
            return a.employee_id
        ad = self.linked_ad(a)
        return ad.employee_id if ad else ""

    def person_of(self, a: Account) -> Person | None:
        return self.person_by_id.get(key(self.employee_id_of(a)))

    def accounts_of(self, p: Person) -> list[Account]:
        return [a for a in self.accounts() if key(self.employee_id_of(a)) == key(p.employee_id)]

    def is_service(self, a: Account) -> bool:
        names = {key(a.name), key(a.sam), key(a.name.split("@")[0])}
        return bool(names & set(self.service_by_name)) or bool(self._svc and self._svc.search(a.name))

    def is_registered_service(self, a: Account) -> bool:
        return bool({key(a.name), key(a.sam), key(a.name.split("@")[0])} & set(self.service_by_name))

    def is_break_glass(self, a: Account) -> bool:
        return bool({key(a.name), key(a.sam), key(a.upn)} & self.break_glass)

    def is_admin(self, a: Account) -> bool:
        return bool(self._admin and self._admin.search(a.name))

    def kind(self, a: Account) -> str:
        if self.is_break_glass(a):
            return "break-glass"
        if a.guest:
            return "guest"
        if self.is_service(a):
            return "service"
        if self.is_admin(a):
            return "admin"
        return "standard"

    def last_activity(self, a: Account) -> datetime | None:
        """Most recent sign-in of the account, counting the other side of a synced pair."""
        other = self.linked_entra(a) if a.directory == "AD" else self.linked_ad(a)
        ts = [t for t in (a.last_logon, other.last_logon if other else None) if t]
        return max(ts) if ts else None

    # -------- access
    def groups_of(self, a: Account) -> list[str]:
        names = {key(a.name)}
        if a.directory == "Entra":
            names.add(key(a.sam))
        out: set[str] = set()
        for n in names:
            out |= self._groups.get(n, set())
        return sorted(out, key=key)

    def catalogue_groups_of(self, a: Account) -> list[Entitlement]:
        return [self.entitlement[key(g)] for g in self.groups_of(a) if key(g) in self.entitlement]

    def tier0_groups_of(self, a: Account) -> list[str]:
        return [g for g in self.groups_of(a) if key(g) in self.tier0]

    def roles_of(self, a: Account) -> list[RoleAssignment]:
        """Directory roles of the account; for a synced pair they belong to the Entra ID side."""
        if a.directory == "AD" and self.linked_entra(a):
            return []
        names = {key(a.name), key(a.upn)} - {""}
        return [r for r in self.roles if key(r.principal) in names]

    def is_member(self, member: str, group: str) -> bool:
        a = self.account(member)
        names = {key(member)} | ({key(a.name)} if a else set())
        return any(key(group) in {key(g) for g in self._groups.get(n, set())} for n in names)

    def vaulted(self, a: Account) -> PamAccount | None:
        return self.pam_by_name.get(key(a.name)) or self.pam_by_name.get(key(a.name.split("@")[0]))

    def find_person(self, ref: str) -> Person | None:
        """An owner or manager written as employee ID, name or account."""
        if not ref:
            return None
        p = self.person_by_id.get(key(ref))
        if p:
            return p
        a = self.account(ref)
        if a and self.person_of(a):
            return self.person_of(a)
        n = _norm(ref)
        return next((x for x in self.people if _norm(x.name) == n), None)


def _opt(folder: Path, names: tuple[str, ...], fn, sources: dict):
    for n in names:
        if (folder / n).exists():
            rows = fn(folder / n)
            sources[n] = len(rows)
            return rows
    return []


def load(folder: Path, as_of: datetime | date | None = None) -> Data:
    folder = Path(folder)
    if not (folder / "hr.csv").exists():
        raise FileNotFoundError(f"{folder / 'hr.csv'} not found: the HR roster is required")
    sp = folder / "settings.json"
    s = settings_from_dict(json.loads(sp.read_text(encoding="utf-8"))) if sp.exists() else Settings()
    people = load_hr(folder / "hr.csv")
    if not people:
        raise ValueError("hr.csv has no rows with an employee ID")
    if isinstance(as_of, date) and not isinstance(as_of, datetime):
        as_of = datetime.combine(as_of, datetime.min.time()) + timedelta(hours=9)
    when = as_of or s.as_of or datetime.now().replace(second=0, microsecond=0)
    src = {"hr.csv": len(people)}
    ad = _opt(folder, ("ad-users.csv",), load_ad, src)
    entra = _opt(folder, ("entra-users.csv",), load_entra, src)
    if not ad and not entra:
        raise FileNotFoundError(f"neither ad-users.csv nor entra-users.csv found in {folder}")
    return Data(s, when, people, ad, entra, _opt(folder, ("memberships.csv",), load_memberships, src),
                _opt(folder, ("entitlements.csv",), load_catalogue, src), _opt(folder, ("privileged-roles.csv",), load_roles, src),
                _opt(folder, ("pam-accounts.csv",), load_pam, src), _opt(folder, ("service-register.csv",), load_service, src),
                _opt(folder, ("recert-results.csv",), load_recert, src), src)


def days(a: date | datetime | None, b: date | datetime | None) -> int | None:
    if a is None or b is None:
        return None
    a = a.date() if isinstance(a, datetime) else a
    b = b.date() if isinstance(b, datetime) else b
    return (b - a).days
