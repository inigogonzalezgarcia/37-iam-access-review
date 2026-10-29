"""Fictional demo: Woodgrove Clearing, a made-up clearing house of about 600 people, reviewed on Thursday 1 October 2026 for September:
the HR roster, Active Directory and Entra ID users, group memberships, the entitlement catalogue, Entra ID roles, the PAM vault, the
service account register and the Q3 recertification campaign, with the problems placed on purpose among the everyday records.
Every name, domain and address is made up."""
from __future__ import annotations

import csv
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

ORG = "Woodgrove Clearing · IAM operations"
AS_OF = datetime(2026, 10, 1, 9, 0)
PERIOD = date(2026, 9, 1)
SEED = 37
DOMAIN = "woodgroveclearing.example"
DC = "DC=corp,DC=woodgroveclearing,DC=example"
CAMPAIGN = "2026-Q3 access recertification"
CAMPAIGN_START, CAMPAIGN_DUE = date(2026, 9, 1), date(2026, 9, 25)

DEPTS = [  # name, code, size, location, head
    ("Executive", "EXE", 5, "Madrid", "Helena Marsh"),
    ("Trading Operations", "TOP", 66, "London", "Samuel Achterberg"),
    ("Clearing Operations", "CLO", 141, "Madrid", "Owen Marsh"),
    ("Risk Management", "RSK", 58, "London", "Priya Raman"),
    ("Settlement", "STL", 54, "Madrid", "Jorge Valcárcel"),
    ("Treasury", "TRS", 25, "Frankfurt", "Ingrid Solberg"),
    ("Finance", "FIN", 35, "Madrid", "Paula Lindqvist"),
    ("Technology", "TEC", 94, "Madrid", "Marcus Webb"),
    ("Information Security", "ISC", 15, "Madrid", "Nadia Brennan"),
    ("Compliance", "CMP", 20, "London", "Elliot Fairbanks"),
    ("Human Resources", "HRS", 15, "Madrid", "Carmen Ibáñez"),
    ("Legal", "LEG", 10, "London", "Ruth Okonkwo"),
    ("Client Services", "CLS", 62, "Madrid", "Daniel Moreau"),
]
FIRST = ["Adrian", "Alba", "Alice", "Amir", "Ana", "Andrea", "Arturo", "Beatriz", "Bruno", "Camille", "Carlos", "Chloe", "Clara", "Cristina",
         "David", "Diego", "Elena", "Emma", "Erik", "Eva", "Felix", "Fiona", "Gabriel", "Grace", "Hannah", "Hugo", "Ines", "Isaac", "Ivan",
         "Jakob", "Javier", "Julia", "Karin", "Laura", "Leo", "Lucas", "Lucia", "Maria", "Marta", "Martin", "Mateo", "Mia", "Nicolas", "Nora",
         "Oliver", "Olga", "Pablo", "Patricia", "Pedro", "Raquel", "Rosa", "Ruben", "Sara", "Sergio", "Sofia", "Teresa", "Tobias", "Victor",
         "Yara", "Zoe"]
LAST = ["Abad", "Aldana", "Arnaiz", "Bauer", "Benitez", "Blanco", "Brandt", "Cano", "Carvalho", "Castro", "Cortes", "Delgado", "Dietrich",
        "Duarte", "Eriksen", "Escobar", "Ferrer", "Fischer", "Fuentes", "Gallardo", "Garrido", "Hartmann", "Herrera", "Iglesias", "Jansen",
        "Keane", "Klein", "Lorenzo", "Lozano", "Madsen", "Marin", "Mendez", "Molina", "Navarro", "Nieto", "Ortega", "Pardo", "Pascual",
        "Peters", "Quintana", "Ramos", "Reyes", "Rojas", "Romero", "Rubio", "Sanz", "Schmidt", "Serrano", "Soler", "Suarez", "Torres",
        "Urquijo", "Vega", "Vidal", "Vogel", "Weber", "Winter", "Yanez", "Zamora", "Zimmer"]

# catalogue: group, application, tier, department tag, recert days, last certified, source directory
CATALOGUE = [
    ("Domain Admins", "Active Directory (corp)", 0, "", 30, "2026-08-05", "AD"),
    ("Enterprise Admins", "Active Directory (forest)", 0, "", 30, "2026-09-02", "AD"),
    ("Schema Admins", "Active Directory (forest)", 0, "", 30, "2026-09-02", "AD"),
    ("APP-ClearTrade-Trader", "ClearTrade trading platform", 1, "Trading Operations", 90, "2026-03-20", "AD"),
    ("APP-RiskEngine-Analyst", "Risk engine", 1, "Risk Management", 90, "2026-03-20", "AD"),
    ("APP-Margin-Admin", "Margin calculator administration", 1, "Risk Management", 90, "2026-03-20", "AD"),
    ("APP-SettleNet-Operator", "SettleNet settlement", 1, "Settlement", 90, "2026-03-20", "AD"),
    ("APP-SWIFT-Alliance-Operator", "SWIFT Alliance Access", 1, "Treasury", 90, "2026-03-20", "AD"),
    ("APP-ClearTrade-ReadOnly", "ClearTrade trading platform", 2, "Clearing Operations", 180, "2026-03-20", "AD"),
    ("APP-Treasury-Cash", "Treasury cash management", 2, "Treasury", 180, "2026-03-20", "AD"),
    ("APP-SAP-FI-Poster", "SAP FI journal posting", 2, "Finance", 180, "2026-03-20", "AD"),
    ("APP-HRIS-HRBP", "HR information system", 2, "Human Resources", 180, "2026-03-20", "Entra"),
    ("FS-Compliance-Restricted", "Compliance restricted share", 2, "Compliance", 180, "2026-03-20", "AD"),
    ("FS-Legal-Contracts", "Legal contracts share", 2, "Legal", 180, "2026-03-20", "AD"),
    ("APP-Splunk-SecOps", "Splunk security operations", 2, "Information Security", 180, "2026-03-20", "Entra"),
    ("APP-CRM-ClientServices", "Client CRM", 3, "Client Services", 365, "2025-11-10", "Entra"),
    ("APP-ServiceNow-ITIL", "ServiceNow ITIL role", 3, "Technology", 365, "2025-11-10", "Entra"),
    ("GG-AllStaff", "All staff", 3, "", 0, "", "AD"),
    ("VPN-Users", "Remote access VPN", 3, "", 0, "", "AD"),
]
DEPT_GROUPS = {"Trading Operations": ["APP-ClearTrade-Trader"], "Clearing Operations": ["APP-ClearTrade-ReadOnly"],
               "Risk Management": ["APP-RiskEngine-Analyst"], "Settlement": ["APP-SettleNet-Operator"], "Treasury": ["APP-Treasury-Cash"],
               "Finance": ["APP-SAP-FI-Poster"], "Technology": ["APP-ServiceNow-ITIL"], "Information Security": ["APP-Splunk-SecOps"],
               "Compliance": ["FS-Compliance-Restricted"], "Human Resources": ["APP-HRIS-HRBP"], "Legal": ["FS-Legal-Contracts"],
               "Client Services": ["APP-CRM-ClientServices"]}
CAMPAIGN_TIERS = (1, 2)

# people placed on purpose: key, name, sam, department
PLANTED = [
    ("akeller", "Anna Keller", "akeller", "Technology"), ("bnakamura", "Ben Nakamura", "bnakamura", "Technology"),
    ("coconnor", "Ciaran O'Connor", "coconnor", "Technology"), ("tnovak", "Tomas Novak", "tnovak", "Technology"),
    ("rkowalski", "Rafael Kowalski", "rkowalski", "Technology"), ("lbrandt", "Lena Brandt", "lbrandt", "Technology"),
    ("dfoster", "Dana Foster", "dfoster", "Information Security"),
    ("vhale", "Viktor Hale", "vhale", "Technology"),                        # leaver, still enabled, adm-vhale in Domain Admins
    ("lgrant", "Lucas Grant", "lgrant", "Trading Operations"),              # leaver, signed in after leaving
    ("mpoole", "Maya Poole", "mpoole", "Client Services"),                  # leaver, still enabled
    ("jwest", "Jonas West", "jwest", "Clearing Operations"),                # leaver, still enabled
    ("ksato", "Kenji Sato", "ksato", "Settlement"),                         # leaver, disabled but still in SettleNet
    ("ewhite", "Esther White", "ewhite", "Client Services"),                # leaver on the last day, inside the grace
    ("hlindqvist", "Hugo Lindqvist", "hlindqvist", "Technology"),           # left in August; owner of svc-clearing-batch
    ("cdubois", "Claire Dubois", "cdubois", "Finance"),                     # mover from Trading Operations, kept the trader role
    ("rpatel", "Rohan Patel", "rpatel", "Risk Management"),                 # mover inside the grace
    ("mrivera", "Marco Rivera", "mrivera", "Settlement"),                   # duplicate employee ID with mrivera2
    ("sbianchi", "Silvia Bianchi", "sbianchi", "Risk Management"),          # future joiner already signed in
    ("ahughes", "Aaron Hughes", "ahughes", "Client Services"),              # joiner without a manager
]
SERVICE = [  # account, owner key, purpose, interactive allowed, last change days ago (PAM), interactive sign-in observed
    ("svc-clearing-batch", "hlindqvist", "End-of-day clearing batch on CLR-BATCH-01", "Yes", 21, "2026-09-27 22:41:05"),
    ("svc-reporting", "", "Nightly regulatory reporting extracts", "No", None, ""),
    ("svc-sqlprod", "akeller", "SQL Server service on CLR-SQL-01/02", "No", 200, ""),
    ("svc-backup", "coconnor", "Backup agent and media server", "No", 35, ""),
    ("svc-swift-gw", "head:Treasury", "SWIFT gateway file transfer", "No", 40, ""),
    ("svc-mft", "tnovak", "Managed file transfer to members", "No", 50, "2026-09-15 10:12:44"),
    ("svc-scan", "coconnor", "Scan to folder on office printers", "No", None, ""),
    ("svc-monitoring", "bnakamura", "Monitoring collector (WMI)", "No", None, ""),
]


def _dt(t: datetime | None, iso: bool = False) -> str:
    if not t:
        return ""
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if iso else t.strftime("%Y-%m-%d %H:%M:%S")


def _d(t: date | None) -> str:
    return t.isoformat() if t else ""


def _rows() -> dict[str, list]:
    rnd = random.Random(SEED)
    today = AS_OF.date()
    used_sam: set[str] = {p[2] for p in PLANTED} | {"test.migration", "jbarker"}
    used_names: set[str] = {p[1] for p in PLANTED} | {d[4] for d in DEPTS}
    people: list[dict] = []
    seq = [10001]

    def new_id() -> str:
        seq[0] += rnd.choice([1, 2, 3])
        return f"WC{seq[0]}"

    def sam_for(name: str) -> str:
        f, l_ = name.split(" ", 1)
        base = (f[0] + l_.replace(" ", "").replace("'", "")).lower()
        base = base.translate(str.maketrans("áéíóúñ", "aeioun"))
        s, k = base, 2
        while s in used_sam:
            s, k = f"{base}{k}", k + 1
        used_sam.add(s)
        return s

    def person(name, dept, sam=None, start=None, **kw) -> dict:
        p = dict(id=new_id(), name=name, dept=dept, sam=sam or sam_for(name), start=start or date(2012, 1, 9) + timedelta(days=rnd.randint(0, 5000)),
                 end=None, moved=None, prev="", manager="", status="Active", key=kw.pop("key", ""))
        p.update(kw)
        people.append(p)
        return p

    heads = {}
    for name, code, size, loc, head in DEPTS:
        h = person(head, name, start=date(2014, 3, 3) + timedelta(days=rnd.randint(0, 1500)))
        heads[name] = h
    ceo = heads["Executive"]
    for name, code, size, loc, head in DEPTS:
        heads[name]["manager"] = ceo["id"] if name != "Executive" else ""
    planted = {}
    for k, name, sam, dept in PLANTED:
        planted[k] = person(name, dept, sam=sam, key=k)
    counts = {d: sum(p["dept"] == d for p in people) for d, *_ in DEPTS}
    for name, code, size, loc, head in DEPTS:
        while counts[name] < size:
            while True:
                n = f"{rnd.choice(FIRST)} {rnd.choice(LAST)}"
                if n not in used_names:
                    used_names.add(n)
                    break
            person(n, name)
            counts[name] += 1
    # managers and the planted HR events
    for p in people:
        if not p["manager"] and p is not ceo and p is not heads.get(p["dept"]):
            p["manager"] = heads[p["dept"]]["id"]
    for k, end in (("vhale", date(2026, 9, 11)), ("lgrant", date(2026, 9, 18)), ("mpoole", date(2026, 9, 25)), ("jwest", date(2026, 9, 29)),
                   ("ksato", date(2026, 9, 16)), ("ewhite", date(2026, 9, 30)), ("hlindqvist", date(2026, 8, 14))):
        planted[k].update(end=end, status="Terminated")
    planted["cdubois"].update(moved=date(2026, 8, 10), prev="Trading Operations")
    planted["rpatel"].update(moved=date(2026, 9, 24), prev="Settlement")
    planted["sbianchi"].update(start=date(2026, 10, 5), status="Pending hire")
    planted["ahughes"].update(start=date(2026, 9, 14), manager="")
    # everyday leavers (September and the summer), movers and joiners
    pool = [p for p in people if not p["key"] and p not in heads.values() and p["dept"] != "Clearing Operations"]   # keeps the 140 items of the rubber stamp
    rnd.shuffle(pool)
    for p in pool[:8]:                                                                 # September leavers, processed on time
        p.update(end=date(2026, 9, 1) + timedelta(days=rnd.randint(0, 28)), status="Terminated")
    for p in pool[8:18]:                                                               # summer leavers
        p.update(end=date(2026, 6, 1) + timedelta(days=rnd.randint(0, 85)), status="Terminated")
    moved_ok = []
    for p in pool[18:22]:                                                              # movers whose old access was removed
        new = rnd.choice([d for d in DEPT_GROUPS if d not in (p["dept"], "Clearing Operations")])
        p.update(prev=p["dept"], dept=new, moved=date(2026, 7, 6) + timedelta(days=rnd.randint(0, 75)), manager=heads[new]["id"])
        moved_ok.append(p)
    for p in pool[22:30]:                                                              # September joiners
        p.update(start=date(2026, 9, 1) + timedelta(days=rnd.choice([0, 7, 14, 21])))
    for p, st in zip(pool[30:32], (date(2026, 10, 12), date(2026, 10, 19))):         # future joiners, accounts pre-created and disabled
        p.update(start=st, status="Pending hire")
    inactive = pool[32:39]                                                             # long leave: no sign-in for months
    pne = pool[39:44]                                                                  # password never expires on a human account
    for p in people:
        p["cc"] = f"CC-{next(c for d, c, *_ in DEPTS if d == p['dept'])}-{rnd.choice([10, 20, 30])}"
        p["loc"] = next(loc for d, _, _, loc, _ in DEPTS if d == p["dept"])

    def left(p) -> bool:
        return p["end"] is not None and p["end"] <= today

    # ------------------------------------------------ access as it was on 1 September (the campaign snapshot)
    def dept_at(p, when: date) -> str:
        return p["prev"] if p["moved"] and p["moved"] > when else p["dept"]

    def active_at(p, when: date) -> bool:
        return p["start"] <= when and (p["end"] is None or p["end"] >= when)

    access: dict[str, set[str]] = {}
    for p in people:
        if active_at(p, CAMPAIGN_START):
            g = {"GG-AllStaff", "VPN-Users"} | set(DEPT_GROUPS.get(dept_at(p, CAMPAIGN_START), []))
            if p is planted["cdubois"]:
                g |= {"APP-ClearTrade-Trader"}                                          # kept from Trading Operations
            access[p["sam"]] = g
    risk = [p for p in people if p["dept"] == "Risk Management" and p["sam"] in access and not p["key"]]
    for p in risk[:8]:
        access[p["sam"]].add("APP-Margin-Admin")
    treasury = [p for p in people if p["dept"] == "Treasury" and p["sam"] in access]
    for p in treasury[:12]:
        access[p["sam"]].add("APP-SWIFT-Alliance-Operator")

    # ------------------------------------------------ the campaign
    ent = {c[0]: c for c in CATALOGUE}
    by_sam = {p["sam"]: p for p in people}
    owner_of = {g: heads[c[3]] for g, c in ent.items() if c[3] in heads}
    items = []
    for sam in sorted(access):
        for g in sorted(access[sam]):
            if ent[g][2] not in CAMPAIGN_TIERS:
                continue
            o = owner_of[g]
            rev = ceo if o["sam"] == sam else o
            items.append(dict(group=g, user=sam, reviewer=rev["name"], decision="", decided=None, removed=None))
    revokes = {("APP-RiskEngine-Analyst", 0): (date(2026, 9, 8), 1), ("APP-RiskEngine-Analyst", 1): (date(2026, 9, 8), 2),
               ("APP-SettleNet-Operator", 0): (date(2026, 9, 9), 1), ("APP-SettleNet-Operator", 1): (date(2026, 9, 9), 9),
               ("APP-SettleNet-Operator", 2): (date(2026, 9, 10), None), ("APP-SAP-FI-Poster", 0): (date(2026, 9, 15), None),
               ("APP-SAP-FI-Poster", 1): (date(2026, 9, 15), "silent"), ("FS-Compliance-Restricted", 0): (date(2026, 9, 11), 3)}
    seen: dict[str, int] = {}
    stamp = datetime(2026, 9, 24, 16, 58, 7)
    stamped = 0
    removed_silently = set()
    for it in items:
        g = it["group"]
        u = by_sam[it["user"]]
        if it["reviewer"] == "Owen Marsh":                                              # 140 approvals in three minutes
            it.update(decision="Approve", decided=stamp + timedelta(seconds=round(stamped * 1.25)))
            stamped += 1
            continue
        if g == "APP-SWIFT-Alliance-Operator":                                         # never reviewed
            continue
        cand = not u["key"] and not left(u) and u["dept"] == ent[g][3]
        n = seen.get(g, 0)
        if cand and (g, n) in revokes:
            seen[g] = n + 1
            day, lag = revokes[(g, n)]
            t = datetime.combine(day, datetime.min.time()) + timedelta(hours=10, minutes=rnd.randint(0, 300), seconds=rnd.randint(0, 59))
            it.update(decision="Revoke", decided=t)
            if isinstance(lag, int):
                it["removed"] = t + timedelta(days=lag, hours=1)
                access[u["sam"]].discard(g)
            elif lag == "silent":
                removed_silently.add((u["sam"], g))
                access[u["sam"]].discard(g)
            continue
        day = CAMPAIGN_START + timedelta(days=rnd.randint(2, 23))
        it.update(decision="Approve", decided=datetime.combine(day, datetime.min.time()) + timedelta(hours=rnd.randint(8, 18), minutes=rnd.randint(0, 59),
                                                                                                        seconds=rnd.randint(0, 59)))

    # ------------------------------------------------ access today
    for p in people:
        sam = p["sam"]
        if left(p) and p["key"] not in ("vhale", "lgrant", "mpoole", "jwest", "ksato", "ewhite"):
            access.pop(sam, None)
        elif p["key"] == "ksato":
            access[sam] = {"APP-SettleNet-Operator"}
        elif p in moved_ok:
            access[sam] = {"GG-AllStaff", "VPN-Users"} | set(DEPT_GROUPS.get(p["dept"], []))
        elif p["key"] == "rpatel":
            access[sam] = access.get(sam, set()) | set(DEPT_GROUPS[p["dept"]])
        elif p["start"] > CAMPAIGN_START and p["start"] <= today:
            access[sam] = {"GG-AllStaff", "VPN-Users"} | set(DEPT_GROUPS.get(p["dept"], []))
    access["sbianchi"] = {"GG-AllStaff", "VPN-Users", "APP-RiskEngine-Analyst"}
    admins = {"adm-akeller": "akeller", "adm-bnakamura": "bnakamura", "adm-coconnor": "coconnor", "adm-vhale": "vhale", "adm-tnovak": "tnovak",
              "adm-lbrandt": "lbrandt"}
    access["adm-akeller"] = {"Domain Admins", "Enterprise Admins"}
    for a in ("adm-bnakamura", "adm-coconnor", "adm-vhale", "adm-tnovak"):
        access[a] = {"Domain Admins"}
    access["adm-lbrandt"] = set()
    access["test.migration"] = {"GG-AllStaff", "APP-Margin-Admin"}
    access["jbarker"] = {"GG-AllStaff", "VPN-Users", "FS-Compliance-Restricted"}
    access["mrivera2"] = {"GG-AllStaff", "APP-SettleNet-Operator"}
    access["svc-ftp-legacy"] = set()
    for s in SERVICE:
        access.setdefault(s[0], set())

    # ------------------------------------------------ AD and Entra ID users
    ad, entra = [], []

    def recent(lo=0, hi=9) -> datetime:
        return AS_OF - timedelta(days=rnd.randint(lo, hi), hours=rnd.randint(1, 14), minutes=rnd.randint(0, 59), seconds=rnd.randint(0, 59))

    def dn(groups) -> str:
        return ";".join(f"CN={g},OU=Groups,{DC}" if g.startswith(("APP", "FS", "GG", "VPN")) else f"CN={g},CN=Users,{DC}"
                        for g in sorted(groups) if ent.get(g, ("", "", 0, "", 0, "", "AD"))[6] == "AD")

    for p in sorted(people, key=lambda x: x["sam"]):
        sam = p["sam"]
        created = datetime.combine(p["start"] - timedelta(days=7), datetime.min.time()) + timedelta(hours=10, minutes=rnd.randint(0, 59))
        enabled = p["start"] <= today and not left(p)
        last = recent() if enabled else None
        if left(p):
            last = datetime.combine(p["end"], datetime.min.time()) + timedelta(hours=17, minutes=rnd.randint(0, 59))
        if p in inactive:
            last = AS_OF - timedelta(days=rnd.randint(120, 200), hours=3)
        if p is inactive[-1]:
            last = None
            created = datetime(2026, 3, 2, 10, 15)
        if p["key"] in ("vhale", "lgrant", "mpoole", "jwest", "ewhite"):
            enabled = True
        if p["key"] == "lgrant":
            last = datetime(2026, 9, 22, 7, 48, 31)
        if p["key"] == "sbianchi":
            enabled, last = True, datetime(2026, 9, 28, 18, 5, 12)
        if p["key"] == "bnakamura":
            last = datetime(2026, 7, 20, 9, 30, 0)
        if p["key"] == "akeller":
            last = datetime(2026, 10, 1, 7, 49, 12)                                      # signed in to activate Global Administrator
        if p["start"] > today and p["key"] != "sbianchi":
            enabled, last = False, None
        pwd = (last or created) - timedelta(days=rnd.randint(3, 80))
        pne_flag = any(x is p for x in pne)
        groups = access.get(sam, set())
        ad.append([sam, p["id"], "True" if enabled else "False", _dt(last), _dt(max(pwd, created)), "True" if pne_flag else "False", _dt(created),
                   dn(groups), f"{p['dept']} · {p['name']}", f"{sam}@{DOMAIN}", p["name"]])
        ent_last = last
        if p["key"] == "lgrant":
            ent_last = datetime(2026, 9, 22, 7, 48, 31)
        mfa = "False" if p["key"] == "dfoster" else ("True" if enabled or left(p) else "")
        entra.append([f"{sam}@{DOMAIN}", p["id"], "True" if enabled else "False", "Member", _dt(created, True), _dt(ent_last, True),
                      _dt(ent_last, True), _dt(ent_last - timedelta(hours=2) if ent_last else None, True), sam, "", mfa, p["name"]])
    mr = planted["mrivera"]                                       # duplicate account for Marco Rivera, created for a second contract
    ad.append(["mrivera2", mr["id"], "True", _dt(recent(5, 30)), _dt(datetime(2026, 6, 2, 9, 0)), "False", _dt(datetime(2026, 6, 1, 11, 20)),
              dn(access["mrivera2"]), "Settlement · contractor account", f"mrivera2@{DOMAIN}", "Marco Rivera (2)"])
    for a, k in admins.items():
        p = planted[k]
        last = recent(0, 6) if k != "vhale" else datetime(2026, 9, 10, 18, 2, 0)
        if k == "tnovak":
            last = datetime(2026, 9, 29, 23, 12, 40)
        ad.append([a, p["id"], "True", _dt(last), _dt(datetime(2026, 9, 1, 2, 0)), "True", _dt(datetime(2021, 2, 1, 9, 0)),
                   dn(access[a]), f"Admin account of {p['name']}", "", f"{p['name']} (admin)"])
    for name, eid, created, last, desc in (("test.migration", "", datetime(2025, 11, 3, 15, 2), datetime(2026, 9, 14, 11, 7, 3), "Migration test 2025"),
                                           ("jbarker", "WC09876", datetime(2019, 4, 8, 9, 0), datetime(2026, 9, 29, 8, 31, 0), "Compliance analyst"),
                                           ("svc-ftp-legacy", "", datetime(2017, 6, 12, 9, 0), datetime(2026, 9, 30, 2, 0, 11), "FTP to members (old)")):
        ad.append([name, eid, "True", _dt(last), _dt(created), "True" if name.startswith("svc") else "False", _dt(created), dn(access[name]), desc, "", name])
    for s in SERVICE:
        last = recent(0, 2)
        ad.append([s[0], "", "True", _dt(last), _dt(AS_OF - timedelta(days=s[4] or 300)), "True", _dt(datetime(2018, 5, 2, 9, 0)), dn(access[s[0]]),
                   s[2], f"{s[0]}@{DOMAIN}", s[0]])
        if s[5] or s[0] == "svc-clearing-batch":
            t = datetime.strptime(s[5], "%Y-%m-%d %H:%M:%S") if s[5] else None
            entra.append([f"{s[0]}@{DOMAIN}", "", "True", "Member", _dt(datetime(2018, 5, 2, 9, 0), True), _dt(t, True), _dt(t, True), _dt(last, True),
                          s[0], "", "", s[0]])
    # cloud-only accounts: break-glass, an orphan and the guests
    for bg in ("bg-admin01", "bg-admin02"):
        entra.append([f"{bg}@{DOMAIN}", "", "True", "Member", _dt(datetime(2022, 1, 10, 9, 0), True), _dt(datetime(2026, 7, 2, 10, 0), True),
                      _dt(datetime(2026, 7, 2, 10, 0), True), "", "", "", "True", f"Break-glass {bg[-2:]}"])
    entra.append([f"audit.temp@{DOMAIN}", "", "True", "Member", _dt(datetime(2026, 7, 1, 12, 0), True), _dt(datetime(2026, 9, 18, 9, 40), True),
                  _dt(datetime(2026, 9, 18, 9, 40), True), "", "", "", "True", "Audit temp"])
    partners = ["fabrikam", "contoso", "litware", "adatum", "northwind", "proseware"]
    techies = [p for p in people if p["dept"] in ("Technology", "Risk Management", "Compliance") and not left(p) and p["start"] <= today]
    for k in range(24):
        f, l_ = FIRST[(k * 7) % len(FIRST)].lower(), LAST[(k * 11 + 3) % len(LAST)].lower()
        dom = partners[k % len(partners)]
        upn = f"{f}.{l_}_{dom}.example#EXT#@{DOMAIN}"
        created = datetime(2025, 3, 1, 9, 0) + timedelta(days=rnd.randint(0, 420))
        last = created + timedelta(days=rnd.randint(1, 15)) if k in (3, 9, 15, 21) else recent(1, 40)
        if k == 21:
            last = None
            created = datetime(2026, 1, 12, 9, 0)
        sponsor = "" if k in (5, 15) else f"{techies[(k * 13) % len(techies)]['sam']}@{DOMAIN}"
        entra.append([upn, "", "True", "Guest", _dt(created, True), _dt(last, True), _dt(last, True), "", "", sponsor, "", f"{f.title()} {l_.title()} ({dom.title()})"])

    # ------------------------------------------------ memberships (catalogue groups, AD and Entra ID)
    memberships = []
    for member in sorted(access):
        for g in sorted(access[member]):
            src = ent[g][6]
            memberships.append([g, member if src == "AD" else f"{member}@{DOMAIN}", src])
    memberships.sort(key=lambda r: (r[0], r[1]))

    # ------------------------------------------------ catalogue
    cat = [[g, app, f"Tier {t}", (heads[dep]["name"] if dep else ("Marcus Webb" if t == 0 else "Carmen Ibáñez")), dep, days or "", "Yes" if t == 0 else "No",
            last] for g, app, t, dep, days, last, _ in CATALOGUE]

    # ------------------------------------------------ Entra ID roles (active instances and eligibilities)
    u = lambda k: f"{k}@{DOMAIN}"  # noqa: E731
    roles = [
        [u("bg-admin01"), "Global Administrator", "Active", "Assigned", "2022-01-10T09:00:00Z", "", "Direct", "/"],
        [u("bg-admin02"), "Global Administrator", "Active", "Assigned", "2022-01-10T09:00:00Z", "", "Direct", "/"],
        [u("rkowalski"), "Global Administrator", "Active", "Assigned", "2026-06-17T14:22:00Z", "", "Direct", "/"],
        [u("akeller"), "Global Administrator", "Eligible", "", "2026-04-01T00:00:00Z", "2027-03-31T23:59:00Z", "Direct", "/"],
        [u("akeller"), "Global Administrator", "Active", "Activated", "2026-10-01T07:55:00Z", "2026-10-01T11:55:00Z", "Direct", "/"],
        [u("bnakamura"), "Global Administrator", "Eligible", "", "2026-04-01T00:00:00Z", "2027-03-31T23:59:00Z", "Direct", "/"],
        [u("coconnor"), "Privileged Role Administrator", "Eligible", "", "2026-04-01T00:00:00Z", "2027-03-31T23:59:00Z", "Direct", "/"],
        [u("dfoster"), "Security Administrator", "Eligible", "", "2026-05-11T00:00:00Z", "2027-05-10T23:59:00Z", "Direct", "/"],
        [u("lbrandt"), "Exchange Administrator", "Active", "Assigned", "2025-09-01T08:00:00Z", "", "Direct", "/"],
        [u("vhale"), "User Administrator", "Eligible", "", "2026-01-15T00:00:00Z", "2027-01-14T23:59:00Z", "Direct", "/"],
        [u("tnovak"), "Intune Administrator", "Eligible", "", "2026-04-01T00:00:00Z", "2027-03-31T23:59:00Z", "Direct", "/"],
    ]
    isec = [p for p in people if p["dept"] == "Information Security" and not p["key"] and not left(p) and p["start"] <= today][:2]
    roles += [[u(p["sam"]), "Security Reader", "Active", "Assigned", "2025-02-03T09:00:00Z", "", "Direct", "/"] for p in isec]
    desk = [p for p in people if p["dept"] == "Technology" and not p["key"] and not left(p) and p["start"] <= today and p not in inactive][:4]
    roles += [[u(p["sam"]), "Helpdesk Administrator", "Active", "Assigned", "2024-10-07T09:00:00Z", "", "Direct", "/"] for p in desk]
    roles.sort(key=lambda r: (r[1], r[0], r[2]))

    # ------------------------------------------------ PAM vault
    def ago(n: int, h: int = 2) -> str:
        return _dt(AS_OF - timedelta(days=n, hours=h))

    pam = [
        ["adm-akeller", "T0-DomainAdmins", "WinDomain", "corp.woodgroveclearing.example", ago(12), ago(0, 3), "Anna Keller", "Yes"],
        ["adm-bnakamura", "T0-DomainAdmins", "WinDomain", "corp.woodgroveclearing.example", ago(12), ago(3), "Ben Nakamura", "Yes"],
        ["adm-coconnor", "T0-DomainAdmins", "WinDomain", "corp.woodgroveclearing.example", ago(12), ago(1), "Ciaran O'Connor", "Yes"],
        ["adm-vhale", "T0-DomainAdmins", "WinDomain", "corp.woodgroveclearing.example", ago(40), ago(21), "Viktor Hale", "Yes"],
        ["adm-lbrandt", "T1-ServerAdmins", "WinDomain", "corp.woodgroveclearing.example", ago(30), ago(9), "Lena Brandt", "Yes"],
        ["bg-admin01", "BreakGlass-Cloud", "CloudBreakGlass", DOMAIN, ago(91), ago(91), "Marcus Webb", "Yes"],
        ["bg-admin02", "BreakGlass-Cloud", "CloudBreakGlass", DOMAIN, ago(91), ago(91), "Marcus Webb", "Yes"],
        ["root", "T1-Unix", "UnixSSH", "clr-db-01.corp.woodgroveclearing.example", ago(6), ago(6), "Ciaran O'Connor", "Yes"],
        ["root", "T1-Unix", "UnixSSH", "clr-db-02.corp.woodgroveclearing.example", ago(6), ago(15), "Ciaran O'Connor", "Yes"],
        ["Administrator", "T1-ServerLocal", "WinServerLocal", "clr-app-07.corp.woodgroveclearing.example", ago(62), ago(30), "Tomas Novak", "No"],
    ]
    for s in SERVICE:
        if s[4] is not None:
            pam.append([s[0], "Svc-Accounts", "WinDomain", "corp.woodgroveclearing.example", ago(s[4]), ago(1), "", "Yes"])
    pam.sort(key=lambda r: (r[1], r[0], r[3]))

    # ------------------------------------------------ service account register
    def owner_ref(k: str) -> str:
        if not k:
            return ""
        if k.startswith("head:"):
            return heads[k[5:]]["id"]
        return planted[k]["id"]
    service = [[s[0], owner_ref(s[1]), s[2], s[3], "AD"] for s in SERVICE]

    # ------------------------------------------------ HR and the campaign results
    hr = [[p["id"], p["name"], p["dept"], p["manager"], p["status"], _d(p["start"]), _d(p["end"]), _d(p["moved"]), p["prev"], p["cc"], p["loc"]]
          for p in sorted(people, key=lambda x: x["id"])]
    recert = []
    for k, it in enumerate(sorted(items, key=lambda x: (x["group"], x["user"]))):
        recert.append([CAMPAIGN, f"Q3-{k + 1:04d}", it["group"], it["user"], it["reviewer"], it["decision"], _dt(it["decided"]), _d(CAMPAIGN_DUE),
                       _dt(it["removed"])])
    ad.sort(key=lambda r: r[0])
    entra.sort(key=lambda r: r[0])
    return dict(hr=hr, ad=ad, entra=entra, memberships=memberships, catalogue=cat, roles=roles, pam=pam, service=service, recert=recert)


FILES = {  # file: (rows key, header)
    "hr.csv": ("hr", ["Employee ID", "Name", "Department", "Manager ID", "Status", "Start date", "End date", "Last movement date",
                      "Previous department", "Cost centre", "Location"]),
    "ad-users.csv": ("ad", ["SamAccountName", "EmployeeID", "Enabled", "LastLogonDate", "PasswordLastSet", "PasswordNeverExpires", "whenCreated",
                            "MemberOf", "Description", "UserPrincipalName", "Name"]),
    "entra-users.csv": ("entra", ["UserPrincipalName", "EmployeeId", "AccountEnabled", "UserType", "CreatedDateTime", "LastSignInDateTime",
                                  "LastSuccessfulSignInDateTime", "LastNonInteractiveSignInDateTime", "OnPremisesSamAccountName", "Sponsors",
                                  "IsMfaRegistered", "DisplayName"]),
    "memberships.csv": ("memberships", ["Group", "Member", "Source"]),
    "entitlements.csv": ("catalogue", ["Group", "Application", "Tier", "Owner", "Department", "Recertify every days", "Privileged", "Last certified"]),
    "privileged-roles.csv": ("roles", ["Principal", "Role", "State", "AssignmentType", "StartDateTime", "EndDateTime", "MemberType",
                                       "DirectoryScopeId"]),
    "pam-accounts.csv": ("pam", ["Account", "Safe", "Platform", "Address", "Last password change", "Last used", "Owner", "Automatic management"]),
    "service-register.csv": ("service", ["Account", "Owner", "Purpose", "Interactive sign-in allowed", "Directory"]),
    "recert-results.csv": ("recert", ["Campaign", "Item ID", "Group", "User", "Reviewer", "Decision", "Decided on", "Due date", "Removed on"]),
}

SETTINGS = {
    "organisation": ORG,
    "as_of": AS_OF.strftime("%Y-%m-%d %H:%M"),
    "period_start": PERIOD.isoformat(),
    "leaver_grace_days": 1,
    "mover_grace_days": 14,
    "joiner_window_days": 30,
    "inactive_days": 90,
    "guest_inactive_days": 90,
    "privileged_inactive_days": 45,
    "pim_roles": ["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator", "Security Administrator",
                  "Exchange Administrator", "SharePoint Administrator", "User Administrator", "Conditional Access Administrator",
                  "Application Administrator", "Cloud Application Administrator", "Intune Administrator", "Authentication Administrator"],
    "critical_roles": ["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator"],
    "break_glass": [f"bg-admin01@{DOMAIN}", f"bg-admin02@{DOMAIN}"],
    "tier0_groups": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators",
                     "Server Operators", "Print Operators"],
    "approved_tier0": ["adm-akeller", "adm-bnakamura", "adm-coconnor", "adm-vhale"],
    "admin_account_pattern": "^(adm|admin)[-_.]",
    "service_account_pattern": "^(svc|sa)[-_.]",
    "pam_rotation_days": 90,
    "pam_rotation_by_platform": {"CloudBreakGlass": 180},
    "vault_required": ["tier0", "admin", "break_glass"],
    "revoke_sla_days": 5,
    "rubber_min_items": 50,
    "rubber_max_minutes": 10,
    "rubber_approve_pct": 100,
    "owners": {"leavers": "IAM operations lead", "movers": "IAM operations lead", "joiners": "HR operations", "accounts": "IAM operations lead",
               "privileged": "Head of infrastructure", "pam": "PAM administrator", "service": "IAM operations lead", "guests": "IAM operations lead",
               "recert": "IAM service owner"},
}


def write(folder: Path) -> Path:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    rows = _rows()
    for name, (k, header) in FILES.items():
        with open(folder / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(header)
            w.writerows(rows[k])
    (folder / "settings.json").write_text(json.dumps(SETTINGS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return folder
