import csv
import hashlib
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path

from iamreview import cli
from iamreview.checks import (CRITICAL, INFO, ORDER, WARNING, account_rows, area_status, entitlement_rows, guest_rows, joiners, leavers, movers,
                              overall, pam_rows, privileged_rows, recert_items, review, reviewers, run_all, service_rows)
from iamreview.model import (Account, Data, Entitlement, Membership, PamAccount, Person, RecertItem, RoleAssignment, ServiceAccount, decision_of,
                             load, load_ad, load_entra, load_hr, parse_dt, settings_from_dict, tier_of)

AS_OF = datetime(2026, 10, 1, 9, 0)
RECENT = datetime(2026, 9, 29, 8, 0)
D = "@corp.example"


def write(path: Path, header: list[str], rows: list[list], delimiter: str = ",") -> Path:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter=delimiter)
        w.writerow(header)
        w.writerows(rows)
    return path


def P(eid, name=None, dept="Finance", manager="M1", **kw) -> Person:
    kw.setdefault("start", date(2020, 1, 6))
    return Person(eid, name or f"Person {eid}", dept, manager, kw.pop("status", "Active"), **kw)


def AD(sam, eid="", **kw) -> Account:
    kw.setdefault("last_logon", RECENT)
    kw.setdefault("created", datetime(2020, 1, 1))
    return Account("AD", sam, eid, **kw)


def EN(name, eid="", **kw) -> Account:
    kw.setdefault("last_logon", RECENT)
    kw.setdefault("created", datetime(2020, 1, 1))
    return Account("Entra", name + D if "@" not in name and "#" not in name else name, eid, upn=name + D, **kw)


def data(people=(), ad=(), entra=(), memberships=(), catalogue=(), roles=(), pam=(), service=(), recert=(), **raw) -> Data:
    s = settings_from_dict({"period_start": "2026-09-01", **raw})
    base = [P("M1", "Manager One", manager="")]
    return Data(s, AS_OF, base + list(people), list(ad), list(entra), list(memberships), list(catalogue), list(roles), list(pam), list(service),
                list(recert))


def codes(rows: list[dict]) -> dict[str, list]:
    out: dict[str, list] = {}
    for r in rows:
        for i in r["issues"]:
            out.setdefault(i.code, []).append(i)
    return out


CAT = [Entitlement("Domain Admins", "AD", 0, "Infra", "", 30, True, date(2026, 9, 20)),
       Entitlement("APP-Trader", "Trading platform", 1, "Head of trading", "Trading", 90, False, date(2026, 9, 1)),
       Entitlement("APP-Ledger", "Ledger", 2, "CFO", "Finance", 180, False, date(2026, 9, 1)),
       Entitlement("GG-AllStaff", "All staff", 3, "HR", "", 0, False, None)]


class TestLoading(unittest.TestCase):
    def test_ad_and_entra_exports_with_raw_values(self):
        with tempfile.TemporaryDirectory() as t:
            a = write(Path(t) / "a.csv", ["sAMAccountName", "employeeID", "Enabled", "lastLogonTimestamp", "pwdLastSet", "PasswordNeverExpires",
                                          "whenCreated", "memberOf"],
                      [["jdoe", "E1", "TRUE", "134350560000000000", "0", "False", "03/02/2026 10:15:00",
                        "CN=Domain Admins,CN=Users,DC=corp,DC=example;CN=APP-Trader,OU=Groups,DC=corp,DC=example"]], delimiter=";")
            e = write(Path(t) / "e.csv", ["userPrincipalName", "employeeId", "accountEnabled", "userType", "createdDateTime",
                                          "signInActivity.lastSignInDateTime", "lastNonInteractiveSignInDateTime", "onPremisesSamAccountName",
                                          "isMfaRegistered"],
                      [["jdoe" + D, "", "true", "Member", "2026-02-03T10:15:00Z", "2026-09-20T08:00:00Z", "2026-09-28T07:12:55.123Z", "jdoe", "false"],
                       ["ext_fabrikam.example#EXT#" + D, "", "true", "Guest", "2026-01-05T09:00:00Z", "", "", "", ""]])
            ad, en = load_ad(a), load_entra(e)
        self.assertEqual((ad[0].member_of, ad[0].pwd_last_set, ad[0].enabled), (["Domain Admins", "APP-Trader"], None, True))
        self.assertEqual(ad[0].last_logon, datetime(2026, 9, 28, 8, 0))                       # FILETIME converted
        self.assertEqual((en[1].last_logon, en[1].last_interactive, en[1].sam, en[1].mfa), (datetime(2026, 9, 28, 7, 12, 55),
                                                                                            datetime(2026, 9, 20, 8, 0), "jdoe", False))
        self.assertTrue(en[0].guest)
        d = data([P("E1")], ad, en, catalogue=CAT)
        self.assertEqual(d.person_of(en[1]).employee_id, "E1")                               # Entra user linked through its AD account
        self.assertEqual(d.last_activity(en[1]), datetime(2026, 9, 28, 8, 0))                 # the most recent of the synced pair
        self.assertEqual(d.tier0_groups_of(ad[0]), ["Domain Admins"])

    def test_hr_names_settings_and_required_files(self):
        with tempfile.TemporaryDirectory() as t:
            h = write(Path(t) / "hr.csv", ["Número empleado", "Nombre", "Departamento", "Responsable", "Estado", "Fecha alta", "Fecha baja",
                                           "Fecha movimiento", "Departamento anterior"],
                      [["E1", "Ana", "Finanzas", "M1", "Baja", "01/02/2020", "15/09/2026", "", ""]], delimiter=";")
            p = load_hr(h)[0]
            with self.assertRaises(FileNotFoundError):
                load(Path(t))                                                                  # no hr.csv (the file above is another name)
            (Path(t) / "x").mkdir()
            write(Path(t) / "x" / "hr.csv", ["Employee ID"], [["E1"]])
            with self.assertRaises(FileNotFoundError):
                load(Path(t) / "x")                                                            # no AD or Entra ID export
        self.assertEqual((p.end, p.department, p.left(date(2026, 10, 1))), (date(2026, 9, 15), "Finanzas", True))
        s = settings_from_dict({"inactive_days": "60", "owners": {"pam": "Vault team"}, "pam_rotation_by_platform": {"UnixSSH": 30}})
        self.assertEqual((s.inactive_days, s.owner("pam"), s.owner("leavers"), s.rotation_days("unixssh"), s.rotation_days("WinDomain")),
                         (60, "Vault team", "IAM operations lead", 30, 90))
        self.assertEqual([tier_of(x) for x in ("Tier 0", "1", "High", "Medium", "low", "")], [0, 1, 1, 2, 3, 3])
        self.assertEqual([decision_of(x) for x in ("Approved", "Revoke", "Remove access", "", "Mantener")], ["approve", "revoke", "revoke", "", "approve"])
        self.assertEqual(parse_dt("1758700800"), datetime(2025, 9, 24, 8, 0))                 # Unix seconds from a PAM API


class TestJoinersMoversLeavers(unittest.TestCase):
    def test_leaver_still_enabled_after_the_grace(self):
        people = [P("E1", end=date(2026, 9, 18), status="Terminated"), P("E2", end=date(2026, 9, 30)), P("E3", end=date(2026, 9, 10))]
        ad = [AD("lgrant", "E1", last_logon=datetime(2026, 9, 22, 7, 48)), AD("e2", "E2"), AD("e3", "E3", enabled=False)]
        rows = leavers(data(people, ad))
        iss = codes(rows)
        self.assertEqual([(i.severity, i.code) for i in iss["LVR-01"]], [(CRITICAL, "LVR-01"), (INFO, "LVR-01")])
        self.assertIn("13 days after the end date (18 Sep)", iss["LVR-01"][0].text)
        self.assertIn("signed in after leaving: lgrant (AD) on 22 Sep", iss["LVR-01"][0].text)
        self.assertEqual({r["person"].employee_id: r["verdict"] for r in rows}, {"E1": "action needed", "E2": "clean", "E3": "clean"})

    def test_leaver_groups_and_roles(self):
        people = [P("E1", end=date(2026, 9, 11)), P("E2", end=date(2026, 9, 16))]
        ad = [AD("adm-vhale", "E1"), AD("vhale", "E1", enabled=False), AD("ksato", "E2", enabled=False)]
        en = [EN("vhale", "E1", enabled=False)]
        m = [Membership("Domain Admins", "adm-vhale"), Membership("APP-Trader", "ksato"), Membership("GG-AllStaff", "vhale")]
        roles = [RoleAssignment("vhale" + D, "User Administrator", "Eligible")]
        iss = codes(leavers(data(people, ad, en, m, CAT, roles)))
        lvr2 = sorted(iss["LVR-02"], key=lambda i: i.severity)
        self.assertEqual([i.severity for i in lvr2], [CRITICAL, WARNING])
        self.assertIn("adm-vhale (AD): Domain Admins; roles: User Administrator (eligible)", lvr2[0].text)
        self.assertIn("ksato (AD): APP-Trader", lvr2[1].text)
        self.assertNotIn("GG-AllStaff", lvr2[0].text)                                        # tier 3 baseline groups are not chased

    def test_mover_kept_previous_department(self):
        people = [P("E1", dept="Finance", moved=date(2026, 8, 10), previous_department="Trading"),
                  P("E2", dept="Risk", moved=date(2026, 9, 24), previous_department="Trading"),
                  P("E3", dept="Trading", moved=date(2026, 7, 1), previous_department="Finance")]
        ad = [AD("cdubois", "E1"), AD("rpatel", "E2"), AD("e3", "E3")]
        m = [Membership("APP-Trader", "cdubois"), Membership("APP-Ledger", "cdubois"), Membership("APP-Trader", "rpatel"),
             Membership("APP-Trader", "e3")]
        rows = movers(data(people, ad, memberships=m, catalogue=CAT))
        iss = codes(rows)
        self.assertEqual([i.severity for i in iss["MOV-01"]], [CRITICAL, INFO])
        self.assertIn("moved Trading → Finance on 10 Aug and still holds APP-Trader (Trading platform, tier 1); 38 days past", iss["MOV-01"][0].text)
        self.assertNotIn("APP-Ledger", iss["MOV-01"][0].text)                                 # access of the new department is fine
        self.assertEqual([r["person"].employee_id for r in rows], ["E1", "E2"])               # E3 moved before the period and is clean

    def test_joiners_before_start_and_without_manager(self):
        people = [P("E1", start=date(2026, 10, 5), status="Pending hire"), P("E2", start=date(2026, 9, 14), manager=""),
                  P("E3", start=date(2026, 9, 7), manager="E9"), P("E9", end=date(2026, 8, 1)), P("E4", start=date(2026, 10, 12))]
        ad = [AD("sbianchi", "E1", last_logon=datetime(2026, 9, 28, 18, 5)), AD("e2", "E2"), AD("e3", "E3"),
              AD("e4", "E4", enabled=False, last_logon=None)]
        m = [Membership("APP-Trader", "sbianchi")]
        iss = codes(joiners(data(people, ad, memberships=m, catalogue=CAT)))
        self.assertEqual(len(iss["JNR-01"]), 1)
        self.assertIn("starts 05 Oct; access before the start date: sbianchi (AD) signed in on 28 Sep; sbianchi (AD) already in APP-Trader",
                      iss["JNR-01"][0].text)
        self.assertEqual(sorted(i.text.split(": ")[1] for i in iss["JNR-02"]),
                         ["manager E9 has left", "no manager in the HR record"])


class TestAccounts(unittest.TestCase):
    def test_orphans_and_duplicates(self):
        ad = [AD("test.migration"), AD("jbarker", "WC09876"), AD("svc-ftp"), AD("svc-batch"), AD("mrivera", "E1"), AD("mrivera2", "E1"),
              AD("old", "", enabled=False), AD("e2", "E2")]
        en = [EN("audit.temp"), EN("bg-admin01"), EN("guest#EXT#", user_type="Guest"), EN("e2", "", sam="e2")]
        m = [Membership("APP-Trader", "test.migration")]
        d = data([P("E1"), P("E2")], ad, en, m, CAT, service=[ServiceAccount("svc-batch", "E1")], break_glass=["bg-admin01" + D])
        iss = codes(account_rows(d))
        acc1 = {i.text.split(" ")[0]: i.severity for i in iss["ACC-01"]}
        self.assertEqual(acc1, {"test.migration": CRITICAL, "jbarker": WARNING, "svc-ftp": WARNING, "audit.temp" + D: WARNING})
        self.assertIn("looks like a service account but is not in the register", next(i.text for i in iss["ACC-01"] if i.text.startswith("svc-ftp")))
        self.assertEqual({i.text for i in iss["ACC-02"]}, {"employee ID E1 on 2 AD accounts: mrivera, mrivera2"})

    def test_inactive_and_password_never_expires(self):
        ad = [AD("idle", "E1", last_logon=datetime(2026, 5, 1)), AD("synced", "E2", last_logon=datetime(2026, 5, 1)),
              AD("never", "E3", last_logon=None, created=datetime(2026, 3, 2)), AD("new", "E4", last_logon=None, created=datetime(2026, 9, 20)),
              AD("pne", "E5", pwd_never_expires=True), AD("adm-pne", "E5", pwd_never_expires=True), AD("adm-vaulted", "E5", pwd_never_expires=True)]
        en = [EN("synced", "", sam="synced", last_logon=datetime(2026, 9, 30))]
        d = data([P(f"E{k}") for k in range(1, 6)], ad, en, pam=[PamAccount("adm-vaulted", "T0", "WinDomain", last_change=RECENT, managed=True)])
        iss = codes(account_rows(d))
        self.assertEqual(sorted(i.text.split(" ")[0] for i in iss["ACC-03"]), ["idle", "never"])   # synced: the Entra ID sign-in counts
        self.assertIn("never signed in, created 02 Mar 2026", next(i.text for i in iss["ACC-03"] if i.text.startswith("never")))
        self.assertEqual(sorted(i.text.split(" ")[0] for i in iss["ACC-04"]), ["adm-pne", "pne"])  # the vaulted admin account is exempt


class TestPrivileged(unittest.TestCase):
    def test_standing_roles_and_break_glass(self):
        en = [EN(x, f"E{k}") for k, x in enumerate(("rkowalski", "akeller", "lbrandt", "desk"), 1)] + [EN("bg-admin01")]
        roles = [RoleAssignment("rkowalski" + D, "Global Administrator", "Active", "Assigned"),
                 RoleAssignment("akeller" + D, "Global Administrator", "Eligible"),
                 RoleAssignment("akeller" + D, "Global Administrator", "Active", "Activated", end=datetime(2026, 10, 1, 11, 55)),
                 RoleAssignment("lbrandt" + D, "Exchange Administrator", "Active", "Assigned", end=datetime(2026, 12, 31)),
                 RoleAssignment("desk" + D, "Helpdesk Administrator", "Active", "Assigned"),
                 RoleAssignment("bg-admin01" + D, "Global Administrator", "Active", "Assigned")]
        d = data([P(f"E{k}") for k in range(1, 5)], entra=en, roles=roles, break_glass=["bg-admin01" + D])
        rows = privileged_rows(d)
        prv = [(i.severity, i.text.split(":")[0]) for i in codes(rows)["PRV-01"]]
        self.assertEqual(sorted(prv), sorted([(CRITICAL, "rkowalski" + D), (WARNING, "lbrandt" + D), (INFO, "break-glass bg-admin01" + D)]))
        self.assertIn("until 31 Dec 2026", next(i.text for i in codes(rows)["PRV-01"] if i.severity == WARNING))
        self.assertEqual({r["how"] for r in rows if r["principal"] == "akeller" + D}, {"eligible", "activated"})

    def test_mfa_inactivity_and_tier0_approval(self):
        en = [EN("dfoster", "E1", mfa=False), EN("bnakamura", "E2", last_logon=datetime(2026, 7, 20)), EN("ok", "E3", mfa=True)]
        ad = [AD("adm-akeller", "E3"), AD("adm-tnovak", "E3"), AD("bg-ad", "")]
        m = [Membership("Domain Admins", "adm-akeller"), Membership("Domain Admins", "adm-tnovak"), Membership("Enterprise Admins", "adm-akeller")]
        roles = [RoleAssignment("dfoster" + D, "Security Administrator", "Eligible"), RoleAssignment("bnakamura" + D, "Global Administrator", "Eligible"),
                 RoleAssignment("ok" + D, "Security Administrator", "Eligible")]
        d = data([P("E1"), P("E2"), P("E3")], ad, en, m, CAT, roles, approved_tier0=["adm-akeller"])
        iss = codes(privileged_rows(d))
        self.assertEqual(sorted((i.severity, i.text.split(":")[0]) for i in iss["PRV-02"]),
                         [(CRITICAL, "dfoster" + D), (WARNING, "bnakamura" + D)])
        self.assertIn("no sign-in for 73 days", next(i.text for i in iss["PRV-02"] if i.severity == WARNING))
        self.assertEqual([i.text for i in iss["PRV-03"]], ["adm-tnovak is in Domain Admins and not on the approved Tier 0 list"])

    def test_pam_rotation_and_admin_accounts_not_vaulted(self):
        pam = [PamAccount("svc-sqlprod", "Svc", "WinDomain", last_change=datetime(2026, 3, 15, 7)),
               PamAccount("adm-a", "T0", "WinDomain", last_change=datetime(2026, 6, 15)),
               PamAccount("root", "Unix", "UnixSSH", last_change=datetime(2026, 9, 1), managed=False),
               PamAccount("bg", "BG", "CloudBreakGlass", last_change=datetime(2026, 5, 1))]
        ad = [AD("adm-a", "E1"), AD("adm-tnovak", "E1"), AD("adm-b", "E1"), AD("adm-off", "E1", enabled=False)]
        m = [Membership("Domain Admins", "adm-tnovak")]
        d = data([P("E1")], ad, memberships=m, catalogue=CAT, pam=pam, pam_rotation_by_platform={"CloudBreakGlass": 180})
        iss = codes(pam_rows(d))
        self.assertEqual(sorted((i.severity, i.text.split(" ")[0]) for i in iss["PAM-01"]),
                         [(CRITICAL, "svc-sqlprod"), (WARNING, "adm-a"), (WARNING, "root")])
        self.assertIn("200 days ago (policy 90 days)", next(i.text for i in iss["PAM-01"] if i.severity == CRITICAL))
        self.assertEqual(sorted((i.severity, i.text.split(" ")[0]) for i in iss["PAM-02"]), [(CRITICAL, "adm-tnovak"), (WARNING, "adm-b")])


class TestServiceAndGuests(unittest.TestCase):
    def test_service_account_owner_and_interactive_sign_in(self):
        people = [P("E1", "Hugo Lindqvist", end=date(2026, 8, 14)), P("E2", "Tomas Novak")]
        ad = [AD("svc-batch"), AD("svc-mft"), AD("svc-rep"), AD("svc-ok")]
        en = [EN("svc-batch", sam="svc-batch", last_interactive=datetime(2026, 9, 27, 22, 41)),
              EN("svc-mft", sam="svc-mft", last_interactive=datetime(2026, 9, 15, 10, 12))]
        svc = [ServiceAccount("svc-batch", "E1", interactive=True), ServiceAccount("svc-mft", "Tomas Novak"), ServiceAccount("svc-rep", ""),
               ServiceAccount("svc-ok", "E2")]
        rows = service_rows(data(people, ad, en, service=svc))
        iss = codes(rows)
        self.assertEqual(sorted((i.severity, i.text) for i in iss["SVC-01"]),
                         [(CRITICAL, "svc-batch: owner Hugo Lindqvist left on 14 Aug 2026; account still enabled"),
                          (WARNING, "svc-rep: no owner in the register")])
        self.assertEqual(sorted((i.severity, i.text.split(":")[0]) for i in iss["SVC-02"]), [(CRITICAL, "svc-mft"), (WARNING, "svc-batch")])
        self.assertEqual({r["svc"].account: r["owner_status"] for r in rows}, {"svc-batch": "left", "svc-mft": "active", "svc-rep": "none",
                                                                             "svc-ok": "active"})

    def test_guests_inactive_or_without_sponsor(self):
        en = [EN("a#EXT#", user_type="Guest", last_logon=datetime(2026, 5, 3), sponsors=["x" + D]),
              EN("b#EXT#", user_type="Guest", last_logon=None, created=datetime(2026, 1, 12), sponsors=["x" + D]),
              EN("c#EXT#", user_type="Guest"), EN("d#EXT#", user_type="Guest", sponsors=["x" + D]),
              EN("e#EXT#", user_type="Guest", enabled=False)]
        iss = codes(guest_rows(data(entra=en)))
        self.assertEqual(sorted(i.text for i in iss["GST-01"]), ["a#EXT#: last sign-in 03 May 2026, 151 days ago",
                                                                 "b#EXT#: never signed in since 12 Jan 2026"])
        self.assertEqual([i.text for i in iss["GST-02"]], ["c#EXT#: no sponsor"])


class TestRecertification(unittest.TestCase):
    def test_overdue_items_and_revokes_not_actioned(self):
        t = lambda day, h=10: datetime(2026, 9, day, h)  # noqa: E731
        items = [RecertItem("Q3", "1", "APP-Trader", "u1", "Ingrid", "", None, date(2026, 9, 25)),
                 RecertItem("Q3", "2", "APP-Ledger", "u2", "Ingrid", "", None, date(2026, 9, 25)),
                 RecertItem("Q3", "3", "APP-Ledger", "u3", "Paula", "revoke", t(15), date(2026, 9, 25)),
                 RecertItem("Q3", "4", "APP-Ledger", "u4", "Paula", "revoke", t(15), date(2026, 9, 25)),
                 RecertItem("Q3", "5", "APP-Ledger", "u5", "Paula", "revoke", t(9), date(2026, 9, 25), t(18, 11)),
                 RecertItem("Q3", "6", "APP-Ledger", "u6", "Paula", "revoke", t(29), date(2026, 9, 25)),
                 RecertItem("Q3", "7", "APP-Ledger", "u7", "Paula", "", None, date(2026, 10, 9))]
        d = data(ad=[AD("u3")], memberships=[Membership("APP-Ledger", "u3")], catalogue=CAT, recert=items)
        rows = recert_items(d)
        iss = codes(rows)
        self.assertEqual([(i.severity, i.text.split(" ")[0]) for i in iss["REC-01"]], [(CRITICAL, "u1"), (WARNING, "u2")])
        self.assertEqual([(i.severity, i.text.split(" ")[0]) for i in iss["REC-02"]], [(CRITICAL, "u3"), (WARNING, "u4"), (INFO, "u5")])
        self.assertIn("not removed after 16 days; still a member", iss["REC-02"][0].text)
        self.assertEqual([r["status"] for r in rows], ["no decision, overdue", "no decision, overdue", "revoke pending 16 days", "revoke pending 16 days",
                                                       "revoked, removed in 9 days", "revoke pending 2 days", "open"])

    def test_rubber_stamp_and_entitlements_overdue(self):
        start = datetime(2026, 9, 24, 16, 58, 7)
        fast = [RecertItem("Q3", f"F{k}", "APP-Ledger", f"u{k}", "Owen", "approve", start + timedelta(seconds=round(k * 1.25)), date(2026, 9, 25))
                for k in range(140)]
        slow = [RecertItem("Q3", f"S{k}", "APP-Ledger", f"v{k}", "Priya", "approve", start + timedelta(hours=k), date(2026, 9, 25)) for k in range(60)]
        mixed = fast[:59] + [RecertItem("Q3", "X", "APP-Ledger", "w", "Sam", "revoke", start, date(2026, 9, 25))]
        mixed = [RecertItem("Q3", i.item, i.group, i.user, "Sam", i.decision, i.decided, i.due) for i in mixed]
        m = [Membership("Domain Admins", "adm-a"), Membership("APP-Trader", "t1"), Membership("APP-Ledger", "u1")]
        cat = CAT[:1] + [Entitlement("APP-Trader", "Trading", 1, "", "Trading", 90, False, date(2026, 3, 20))] + CAT[2:]
        cat[0].last_certified = date(2026, 8, 5)
        d = data(ad=[AD("adm-a")], memberships=m, catalogue=cat, recert=fast + slow + mixed)
        revs = reviewers(d, recert_items(d))
        flagged = {r["reviewer"]: [i.text for i in r["issues"]] for r in revs}
        self.assertEqual(flagged["Owen"], ["Owen: approved 140 of 140 items in 3 min (16:58–17:01 on 24 Sep), Q3"])
        self.assertEqual((flagged["Priya"], flagged["Sam"]), ([], []))                     # slow, or not 100% approve
        ents = {r["entitlement"].group: r for r in entitlement_rows(d)}
        self.assertEqual(ents["APP-Ledger"]["last"], date(2026, 9, 27))                    # the campaign decisions count as certification
        self.assertEqual([(i.severity, i.text.split(" (")[0]) for g in ("Domain Admins", "APP-Trader") for i in ents[g]["issues"]],
                         [(CRITICAL, "Domain Admins"), (CRITICAL, "APP-Trader")])
        self.assertIn("27 days overdue (every 30 days)", ents["Domain Admins"]["issues"][0].text)
        self.assertEqual(ents["GG-AllStaff"]["issues"], [])                               # no recertification required


class TestVerdictsAndCommands(unittest.TestCase):
    def test_area_status_overall_and_order(self):
        d = data([P("E1", end=date(2026, 9, 1))], [AD("e1", "E1", enabled=False)], service=[ServiceAccount("svc-x", "")], catalogue=CAT)
        f = run_all(d)
        st = area_status(f)
        self.assertEqual((st["Leavers"], st["Service & guest accounts"], st["Privileged access"]), ("ok", WARNING, "ok"))
        self.assertEqual(overall(f), "follow up")
        self.assertEqual([x.severity for x in f], sorted((x.severity for x in f), key=ORDER.get))
        self.assertEqual(overall(run_all(data([P("E1")], [AD("e1", "E1")]))), "clean")
        rv = review(d)
        self.assertEqual(sorted(rv), ["accounts", "entitlements", "guests", "joiners", "leavers", "movers", "pam", "privileged", "recert", "reviewers",
                                      "service"])

    def test_demo_end_to_end_is_deterministic(self):
        hashes = []
        with tempfile.TemporaryDirectory() as t:
            for k in range(2):
                out = Path(t) / f"out{k}"
                self.assertEqual(cli.main(["demo", "--data", str(Path(t) / f"data{k}"), "--out", str(out)]), 0)
                self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(cli.OUTPUTS))
                files = sorted(p for p in list(out.iterdir()) + list((Path(t) / f"data{k}").iterdir()))
                hashes.append({p.name + str(p.parent.name)[:3]: hashlib.sha1(p.read_bytes()).hexdigest() for p in files})
            self.assertEqual(hashes[0], hashes[1])
            d = load(Path(t) / "data0")
            pack = (Path(t) / "out0" / "access-review.md").read_text(encoding="utf-8")
        rv = review(d)
        f = run_all(d, rv)
        found = {x.code for x in f if x.severity != INFO}
        for c in ("LVR-01", "LVR-02", "MOV-01", "JNR-01", "JNR-02", "ACC-01", "ACC-02", "ACC-03", "ACC-04", "PRV-01", "PRV-02", "PRV-03", "PAM-01",
                  "PAM-02", "SVC-01", "SVC-02", "GST-01", "GST-02", "REC-01", "REC-02", "REC-03", "REC-04"):
            self.assertIn(c, found)
        self.assertEqual((len(d.people), d.settings.organisation), (600, "Woodgrove Clearing · IAM operations"))
        self.assertEqual(sum(1 for r in rv["leavers"] if any(i.code == "LVR-01" and i.severity == CRITICAL for i in r["issues"])), 4)
        self.assertTrue(any("adm-vhale (AD) in Domain Admins" in i.text for r in rv["leavers"] for i in r["issues"]))
        self.assertTrue(any("standing Global Administrator (permanent, Direct" in i.text and i.severity == CRITICAL for r in rv["privileged"]
                            for i in r["issues"]))
        self.assertTrue(any("200 days ago" in i.text for r in rv["pam"] for i in r["issues"]))
        self.assertEqual([(r["reviewer"], r["decided"]) for r in rv["reviewers"] if r["issues"]], [("Owen Marsh", 140)])
        self.assertEqual(overall(f), "action needed")
        self.assertIn("| AC-01 | Leavers' accounts are disabled within 1 day(s) of the HR end date | 14 leavers (14 in the period) | 4 | Not effective |",
                      pack)

    def test_review_reports_missing_files(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(cli.main(["review", t, "--out", str(Path(t) / "o")]), 2)
            write(Path(t) / "hr.csv", ["Employee ID"], [["E1"]])
            self.assertEqual(cli.main(["review", "--data", t, "--out", str(Path(t) / "o")]), 2)
            write(Path(t) / "ad-users.csv", ["SamAccountName", "EmployeeID", "Enabled"], [["e1", "E1", "True"]])
            self.assertEqual(cli.main(["review", t, "--out", str(Path(t) / "o"), "--as-of", "2026-10-01"]), 0)
            self.assertTrue((Path(t) / "o" / "access-review.md").exists())


if __name__ == "__main__":
    unittest.main()
