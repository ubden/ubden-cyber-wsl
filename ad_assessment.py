"""Bounded, read-only directory inventory with an explicitly supplied test user.

Beyond object counts, this reads the domain password policy, the machine
account quota, and Domain Admins membership — all standard read-only LDAP reads
that a normal domain user can perform. They feed *draft* findings (weak password
policy, machine-join by any user, excessive domain admins); the analyst confirms
impact before any becomes verified.
"""
from __future__ import annotations

import re
import ssl
import struct
import uuid


def _as_int(entry, field):
    try:
        value = entry[field].value if field in entry else None
    except Exception:
        return None
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _filetime_days(value):
    """AD stores durations as negative 100-nanosecond intervals; return days."""
    if value in (None, 0):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value >= 0:  # 0x7FFFFFFFFFFFFFFF = never / not set
        return None
    return round(abs(value) / (1e7 * 60 * 60 * 24), 1)


def _password_policy(connection, base):
    """Domain root policy attributes; a normal user can read these."""
    try:
        from ldap3 import BASE
        connection.search(base, "(objectClass=domain)", search_scope=BASE,
                          attributes=["minPwdLength", "pwdHistoryLength", "pwdProperties",
                                      "lockoutThreshold", "lockoutDuration", "maxPwdAge",
                                      "minPwdAge", "ms-DS-MachineAccountQuota", "objectSid"],
                          size_limit=1, time_limit=10)
        if not connection.entries:
            return {}, None, None
        entry = connection.entries[0]
        props = _as_int(entry, "pwdProperties")
        policy = {
            "min_length": _as_int(entry, "minPwdLength"),
            "history_length": _as_int(entry, "pwdHistoryLength"),
            "lockout_threshold": _as_int(entry, "lockoutThreshold"),
            "lockout_duration_min": _filetime_days(entry["lockoutDuration"].value
                                                   if "lockoutDuration" in entry else None),
            "max_pwd_age_days": _filetime_days(entry["maxPwdAge"].value
                                               if "maxPwdAge" in entry else None),
            "complexity_enabled": (bool(props & 0x1) if props is not None else None),
        }
        maq = _as_int(entry, "ms-DS-MachineAccountQuota")
        sid = None
        try:
            sid = str(entry["objectSid"].value) if "objectSid" in entry else None
        except Exception:
            sid = None
        return policy, maq, sid
    except Exception:
        return {}, None, None


def _domain_admins(connection, base, domain_sid):
    """Domain Admins membership. Query by sAMAccountName (constant across locales),
    then by RID-512 SID as a fallback — but only when the SID is a valid string SID
    (with get_info=NONE, objectSid can come back as raw bytes, which would make the
    filter invalid and silently drop the whole finding)."""
    filters = ["(sAMAccountName=Domain Admins)"]
    sid = str(domain_sid) if domain_sid else ""
    if sid.upper().startswith("S-1-"):
        filters.append(f"(objectSid={sid}-512)")
    for filt in filters:
        try:
            connection.search(base, f"(&(objectClass=group){filt})",
                              attributes=["member", "sAMAccountName"],
                              size_limit=1, time_limit=10)
        except Exception:
            continue
        if not connection.entries:
            continue
        entry = connection.entries[0]
        members = []
        try:
            raw = entry["member"].values if "member" in entry else []
        except Exception:
            raw = []
        for dn in raw:
            cn = str(dn).split(",", 1)[0]
            members.append(cn[3:] if cn.lower().startswith("cn=") else cn)
        try:
            group = str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "Domain Admins"
        except Exception:
            group = "Domain Admins"
        return {"group": group, "count": len(members), "members": sorted(members)[:60]}
    return None


# --- Deep enumeration: UAC risk flags, Kerberoast/AS-REP, sensitive groups, computers ---

# userAccountControl bits (values match the standard AD constants).
_UAC_FLAGS = (
    ("disabled", 0x0002, "Devre dışı hesap"),
    ("passwd_notreqd", 0x0020, "Parola gerekmiyor (PASSWD_NOTREQD)"),
    ("reversible_encryption", 0x0080, "Tersinir şifreleme açık"),
    ("password_never_expires", 0x10000, "Parolası hiç bitmiyor (DONT_EXPIRE_PASSWORD)"),
    ("unconstrained_delegation", 0x80000, "Kısıtlanmamış yetkilendirme (unconstrained delegation)"),
    ("asrep_roastable", 0x400000, "Kerberos ön-kimlik doğrulaması kapalı (AS-REP roast)"),
    ("constrained_delegation_proto", 0x1000000, "Protokol geçişli kısıtlı yetkilendirme"),
)
# Sensitive/privileged groups to enumerate membership of (CN, locale-independent enough
# for default domains; missing groups are skipped).
_SENSITIVE_GROUPS = (
    "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
    "Backup Operators", "Server Operators", "Print Operators", "DnsAdmins",
    "Remote Desktop Users", "Protected Users", "Group Policy Creator Owners",
    "Cert Publishers",
)


def _val(entry, attr):
    try:
        value = entry[attr].value if attr in entry else None
    except Exception:
        return ""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return str(value) if value not in (None, "") else ""


def _vals(entry, attr):
    try:
        raw = entry[attr].values if attr in entry else []
    except Exception:
        return []
    return [str(v) for v in raw if v not in (None, "")]


def _cn(dn):
    head = str(dn).split(",", 1)[0]
    return head[3:] if head.lower().startswith("cn=") else head


def _escape_filter(value):
    out = []
    for ch in str(value):
        if ch in "\\*()\x00":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _filetime_dt(entry, attr):
    """Windows FILETIME (100-ns since 1601) or a datetime -> aware datetime, else None."""
    from datetime import datetime, timezone, timedelta
    try:
        value = entry[attr].value if attr in entry else None
    except Exception:
        return None
    if value in (None, 0, "0"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks / 10)
    except (OverflowError, ValueError):
        return None


def _deep_enum(connection, base):
    """UAC risk flags, Kerberoastable/AS-REP users, sensitive-group members and a
    computer inventory (dNSHostName/OS/lastLogon) with forward-resolved IPs. Every read
    is standard read-only LDAP a normal domain user can perform; each block degrades
    independently on error."""
    import socket
    from datetime import datetime, timezone, timedelta
    out = {}
    risky = {key: [] for key, _, _ in _UAC_FLAGS}
    kerberoastable, asrep = [], []
    try:
        connection.search(base, "(&(objectCategory=person)(objectClass=user))",
                          attributes=["sAMAccountName", "userAccountControl",
                                      "servicePrincipalName", "adminCount"],
                          size_limit=5000, time_limit=30)
        for e in connection.entries:
            sam = _val(e, "sAMAccountName")
            if not sam:
                continue
            uac = _as_int(e, "userAccountControl") or 0
            for key, bit, _ in _UAC_FLAGS:
                if uac & bit:
                    risky[key].append(sam)
            spns = _vals(e, "servicePrincipalName")
            if spns and sam.lower() != "krbtgt":
                kerberoastable.append({"account": sam, "spn_count": len(spns),
                                       "admin": bool(_as_int(e, "adminCount"))})
            if (uac & 0x400000) and sam.lower() != "krbtgt":
                asrep.append(sam)
    except Exception:
        pass
    out["risky_accounts"] = {k: sorted(set(v))[:300] for k, v in risky.items() if v}
    out["kerberoastable"] = sorted(kerberoastable, key=lambda x: x["account"])[:300]
    out["asrep_roastable"] = sorted(set(asrep))[:300]

    groups = {}
    for gname in _SENSITIVE_GROUPS:
        try:
            connection.search(base, f"(&(objectCategory=group)(cn={_escape_filter(gname)}))",
                              attributes=["member"], size_limit=1, time_limit=10)
        except Exception:
            continue
        if not connection.entries:
            continue
        members = [_cn(dn) for dn in _vals(connection.entries[0], "member")]
        if members:
            groups[gname] = sorted(members)[:100]
    out["sensitive_groups"] = groups

    computers, os_summary = [], {}
    stale_cut = datetime.now(timezone.utc) - timedelta(days=90)
    try:
        connection.search(base, "(objectCategory=computer)",
                          attributes=["sAMAccountName", "dNSHostName", "operatingSystem",
                                      "operatingSystemVersion", "lastLogonTimestamp"],
                          size_limit=5000, time_limit=30)
        for e in connection.entries:
            name = (_val(e, "sAMAccountName") or "").rstrip("$")
            dns = _val(e, "dNSHostName")
            os_name = _val(e, "operatingSystem")
            key = os_name or "(OS kaydı yok)"
            os_summary[key] = os_summary.get(key, 0) + 1
            when = _filetime_dt(e, "lastLogonTimestamp")
            ip = ""
            if dns:
                try:
                    ip = socket.gethostbyname(dns)
                except OSError:
                    ip = ""
            computers.append({"name": name, "dns": dns, "ip": ip, "os": os_name,
                              "os_version": _val(e, "operatingSystemVersion"),
                              "last_logon": when.date().isoformat() if when else "",
                              "stale": (when is None) or (when < stale_cut)})
    except Exception:
        pass
    out["computers"] = sorted(computers, key=lambda x: x["name"])[:2000]
    out["computer_os_summary"] = dict(sorted(os_summary.items(), key=lambda kv: -kv[1]))
    out["stale_computers"] = sorted(c["name"] for c in computers if c["stale"])[:300]
    # name<->ip map that device_inventory uses to fill hostnames from AD (authoritative).
    out["computer_ip_map"] = {c["ip"]: (c["dns"] or c["name"]) for c in computers if c["ip"]}
    return out


# --- ADCS (AD Certificate Services) passive enumeration: CAs, templates, ESC1-4 ---
# Client-authentication EKUs that let a cert be used to authenticate as its subject.
_CLIENT_AUTH_EKU = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4",
                    "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0"}
# Certificate-Enrollment / -AutoEnrollment extended-right GUIDs.
_ENROLL_GUIDS = {"0e10c968-78fb-11d2-90d4-00c04f79dc55",
                 "a05b8cc2-17bc-4802-a710-e7c15ab866a2"}


def _sid_str(data, off):
    try:
        if off + 8 > len(data):
            return ""
        rev, count = data[off], data[off + 1]
        authority = int.from_bytes(bytes(data[off + 2:off + 8]), "big")
        subs, p = [], off + 8
        for _ in range(count):
            if p + 4 > len(data):
                break
            subs.append(struct.unpack_from("<I", data, p)[0]); p += 4
        return "S-%d-%d%s" % (rev, authority, "".join("-%d" % s for s in subs))
    except Exception:
        return ""


def _parse_dacl(sd):
    """Self-relative SECURITY_DESCRIPTOR bytes -> [{mask, guid, sid}] for Allow ACEs."""
    if not isinstance(sd, (bytes, bytearray)) or len(sd) < 20:
        return []
    offset_dacl = struct.unpack_from("<I", sd, 16)[0]
    if offset_dacl == 0 or offset_dacl + 8 > len(sd):
        return []
    ace_count = struct.unpack_from("<H", sd, offset_dacl + 4)[0]
    out, pos = [], offset_dacl + 8
    for _ in range(ace_count):
        if pos + 4 > len(sd):
            break
        ace_type = sd[pos]
        ace_size = struct.unpack_from("<H", sd, pos + 2)[0]
        if ace_size < 4 or pos + ace_size > len(sd):
            break
        if ace_type in (0x00, 0x05):  # ACCESS_ALLOWED / ACCESS_ALLOWED_OBJECT
            body = pos + 4
            mask = struct.unpack_from("<I", sd, body)[0]
            guid, p = None, body + 4
            if ace_type == 0x05:
                obj_flags = struct.unpack_from("<I", sd, p)[0]; p += 4
                if obj_flags & 0x1:
                    try:
                        guid = str(uuid.UUID(bytes_le=bytes(sd[p:p + 16])))
                    except Exception:
                        guid = None
                    p += 16
                if obj_flags & 0x2:
                    p += 16
            sid = _sid_str(sd, p)
            if sid:
                out.append({"mask": mask, "guid": guid, "sid": sid})
        pos += ace_size
    return out


def _low_priv_sid(sid, domain_sid):
    if sid in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545"):  # Everyone, Authenticated Users, BUILTIN\Users
        return True
    ds = str(domain_sid or "")
    if ds.upper().startswith("S-1-"):
        return sid in (f"{ds}-513", f"{ds}-515")  # Domain Users, Domain Computers
    return False


def _template_low_priv_rights(sd, domain_sid):
    """(low_priv_can_enroll, low_priv_dangerous_write) from a template's DACL, or (None,None)."""
    try:
        aces = _parse_dacl(sd)
    except Exception:
        return None, None
    if not aces:
        return None, None
    enroll = write = False
    for ace in aces:
        if not _low_priv_sid(ace["sid"], domain_sid):
            continue
        mask, guid = ace["mask"], ace["guid"]
        if (mask & 0x100) and (guid is None or guid in _ENROLL_GUIDS):  # DS_CONTROL_ACCESS
            enroll = True
        if mask & (0x10000000 | 0x40000000 | 0x00040000 | 0x00080000):  # GenericAll/Write, WriteDacl/Owner
            write = True
        if (mask & 0x20) and guid is None:  # WriteProperty over all properties
            write = True
    return enroll, write


def _adcs(connection, config_nc, domain_sid):
    """Passive AD CS enumeration over LDAP: CAs, published templates and ESC1-ESC4 candidates.
    Enrollment/write rights come from each template's DACL when it can be read, so results are
    precise (a SAN-free template only admins may enroll is NOT reported). ESC6/ESC7/ESC8 need
    the CA host (certutil/DCOM/HTTP) and are covered by Attack Mode (certipy)."""
    if not config_nc:
        return None
    try:
        from ldap3 import SUBTREE
    except Exception:
        return None
    pki = f"CN=Public Key Services,CN=Services,{config_nc}"
    out = {"cas": [], "templates": [], "esc": []}
    try:
        connection.search(f"CN=Enrollment Services,{pki}", "(objectClass=pKIEnrollmentService)",
                          search_scope=SUBTREE, attributes=["cn", "dNSHostName", "certificateTemplates"],
                          size_limit=50, time_limit=10)
        for e in connection.entries:
            out["cas"].append({"name": _val(e, "cn"), "host": _val(e, "dNSHostName"),
                               "templates": _vals(e, "certificateTemplates")})
    except Exception:
        return None
    if not out["cas"]:
        return None
    published = set()
    for ca in out["cas"]:
        published.update(t.lower() for t in ca["templates"])
    sd_control = None
    try:
        from ldap3.protocol.microsoft import security_descriptor_control
        sd_control = security_descriptor_control(sdflags=0x04)  # DACL only
    except Exception:
        sd_control = None
    attrs = ["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
             "msPKI-RA-Signature", "pKIExtendedKeyUsage", "nTSecurityDescriptor"]
    try:
        connection.search(f"CN=Certificate Templates,{pki}", "(objectClass=pKICertificateTemplate)",
                          search_scope=SUBTREE, attributes=attrs, size_limit=500, time_limit=20,
                          controls=sd_control)
        entries = list(connection.entries)
    except Exception:
        entries = []
    for e in entries:
        name = _val(e, "cn")
        name_flag = _as_int(e, "msPKI-Certificate-Name-Flag") or 0
        enroll_flag = _as_int(e, "msPKI-Enrollment-Flag") or 0
        ra_sig = _as_int(e, "msPKI-RA-Signature") or 0
        ekus = set(_vals(e, "pKIExtendedKeyUsage"))
        san_free = bool(name_flag & 0x1)             # ENROLLEE_SUPPLIES_SUBJECT
        manager_approval = bool(enroll_flag & 0x2)   # PEND_ALL_REQUESTS
        client_auth = bool(ekus & _CLIENT_AUTH_EKU) or not ekus
        any_purpose = ("2.5.29.37.0" in ekus) or not ekus
        enroll_agent = "1.3.6.1.4.1.311.20.2.1" in ekus
        sd = None
        try:
            if "nTSecurityDescriptor" in e and e["nTSecurityDescriptor"].raw_values:
                sd = e["nTSecurityDescriptor"].raw_values[0]
        except Exception:
            sd = None
        can_enroll, can_write = _template_low_priv_rights(sd, domain_sid) if sd else (None, None)
        is_pub = name.lower() in published
        out["templates"].append({"name": name, "published": is_pub, "san_free": san_free,
                                  "manager_approval": manager_approval, "client_auth": client_auth,
                                  "ra_signature": ra_sig, "low_priv_enroll": can_enroll,
                                  "low_priv_write": can_write})
        # Enrollable = published, no manager approval, no RA countersignature, and a low-priv
        # principal can enroll (unknown ACL -> not disproven, still a candidate to review).
        enrollable = is_pub and not manager_approval and ra_sig == 0 and (can_enroll is not False)
        acl_note = "" if can_enroll is True else (" (kayıt hakkı DACL'den doğrulanamadı; teyit edin)" if can_enroll is None else "")
        if enrollable and san_free and client_auth:
            out["esc"].append({"esc": "ESC1", "template": name,
                "detail": "SAN serbest + istemci kimlik-doğrulama EKU + onay yok + RA imza yok; düşük "
                          "yetkili kullanıcı SAN belirterek herhangi biri (DA dahil) adına sertifika alabilir." + acl_note})
        elif enrollable and any_purpose and not san_free:
            out["esc"].append({"esc": "ESC2", "template": name,
                "detail": "Any-Purpose / EKU yok + onay yok; sertifika birçok amaç için kötüye kullanılabilir." + acl_note})
        if enrollable and enroll_agent:
            out["esc"].append({"esc": "ESC3", "template": name,
                "detail": "Certificate Request Agent EKU + düşük yetkili kayıt; başka kullanıcı adına sertifika talep edilebilir." + acl_note})
        if can_write:
            out["esc"].append({"esc": "ESC4", "template": name,
                "detail": "Şablon üzerinde düşük yetkili principal'a tehlikeli yazma hakkı (WriteDacl/WriteOwner/"
                          "GenericAll/GenericWrite/WriteProperty); şablon ESC1'e dönüştürülebilir."})
    return out


def _resolve_sid(connection, base, sid):
    """Resolve a SID string to {name, type} (best-effort)."""
    if not sid:
        return None
    try:
        from ldap3 import SUBTREE
        connection.search(base, f"(objectSid={sid})", search_scope=SUBTREE,
                          attributes=["sAMAccountName", "cn", "objectClass"],
                          size_limit=1, time_limit=8)
        if connection.entries:
            e = connection.entries[0]
            classes = _vals(e, "objectClass")
            kind = "group" if "group" in classes else ("user" if "user" in classes else (classes[-1] if classes else ""))
            return {"sid": sid, "name": _val(e, "sAMAccountName") or _val(e, "cn"), "type": kind}
    except Exception:
        pass
    return None


def _gpo_ou(connection, base):
    """GPOs + where they are linked (gPLink), OU user distribution, and admin-like custom
    groups (e.g. a 'Local Admin' group pushed by policy). Read-only LDAP a normal user runs."""
    try:
        from ldap3 import SUBTREE, LEVEL
    except Exception:
        return {}
    out = {}
    gpos = {}
    try:
        connection.search(f"CN=Policies,CN=System,{base}", "(objectClass=groupPolicyContainer)",
                          search_scope=SUBTREE, attributes=["cn", "displayName"],
                          size_limit=500, time_limit=15)
        for e in connection.entries:
            guid = _val(e, "cn")
            if guid:
                gpos[guid.lower()] = {"guid": guid, "name": _val(e, "displayName"), "links": []}
    except Exception:
        pass
    ous = []
    try:
        connection.search(base, "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                          search_scope=SUBTREE, attributes=["ou", "gPLink", "distinguishedName"],
                          size_limit=2000, time_limit=20)
        for e in connection.entries:
            dn = _val(e, "distinguishedName")
            for guid in re.findall(r"\{[0-9A-Fa-f-]{36}\}", _val(e, "gPLink") or ""):
                g = gpos.get(guid.lower())
                if g and dn not in g["links"]:
                    g["links"].append(dn)
            if _val(e, "ou"):
                ous.append(dn)
    except Exception:
        pass
    if gpos:
        out["gpos"] = sorted(gpos.values(), key=lambda x: (x["name"] or x["guid"]).lower())[:300]
    dist = []
    for dn in ous[:80]:
        try:
            connection.search(dn, "(&(objectCategory=person)(objectClass=user))",
                              search_scope=LEVEL, attributes=["cn"], size_limit=2000, time_limit=10)
            n = len(connection.entries)
            if n:
                dist.append({"ou": dn, "users": n})
        except Exception:
            continue
    if dist:
        out["ou_user_distribution"] = sorted(dist, key=lambda x: -x["users"])[:80]
    admin_groups = {}
    try:
        connection.search(base, "(objectClass=group)", attributes=["sAMAccountName", "member", "description"],
                          size_limit=3000, time_limit=25)
        for e in connection.entries:
            name = _val(e, "sAMAccountName")
            if not name or not re.search(r"admin|yönetici|localadmin|privile|ayrıcalık|yetkili", name, re.I):
                continue
            members = [_cn(dn) for dn in _vals(e, "member")]
            if members:
                admin_groups[name] = {"members": sorted(members)[:100], "description": _val(e, "description")}
    except Exception:
        pass
    if admin_groups:
        out["admin_like_groups"] = admin_groups
    return out


# --- Risky AD: dangerous ACLs on privileged accounts, delegation, RBCD (BloodHound-lite) ---
_DANGER_MASK = 0x10000000 | 0x40000000 | 0x00040000 | 0x00080000  # GenericAll/Write, WriteDacl/Owner
_RESET_PW = "00299570-246d-11d0-a768-00aa006e0529"
_DCSYNC = {"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"}
_KEYCRED = "5b47d60f-6090-40b2-9f37-2a4de88f3063"   # msDS-KeyCredentialLink (shadow creds)


def _safe_sids(domain_sid):
    """Principals that legitimately hold rights over privileged accounts."""
    safe = {"S-1-5-18", "S-1-5-10", "S-1-3-0", "S-1-5-9", "S-1-5-32-544", "S-1-5-32-548"}
    ds = str(domain_sid or "")
    if ds.upper().startswith("S-1-"):
        for rid in (512, 516, 518, 519, 521, 526, 527, 498):
            safe.add(f"{ds}-{rid}")
    return safe


def _sd_dacl_control():
    try:
        from ldap3.protocol.microsoft import security_descriptor_control
        return security_descriptor_control(sdflags=0x04)
    except Exception:
        return None


def _account_acl_risks(connection, dn, base, safe, sd_control, cache):
    """Non-safe principals with takeover/reset/DCSync/shadow-cred rights over `dn`."""
    try:
        from ldap3 import BASE
        connection.search(dn, "(objectClass=*)", search_scope=BASE,
                          attributes=["nTSecurityDescriptor"], controls=sd_control,
                          size_limit=1, time_limit=8)
    except Exception:
        return []
    if not connection.entries:
        return []
    try:
        sd = connection.entries[0]["nTSecurityDescriptor"].raw_values[0]
    except Exception:
        return []
    out = []
    for ace in _parse_dacl(sd):
        sid = ace["sid"]
        if sid in safe or sid.endswith("-500"):
            continue
        mask, guid = ace["mask"], (ace["guid"] or "").lower()
        if mask & _DANGER_MASK:
            right = "Tam kontrol (GenericAll/Write · WriteDacl/Owner)"
        elif (mask & 0x100) and guid == _RESET_PW:
            right = "Parola sıfırlama hakkı"
        elif (mask & 0x100) and guid in _DCSYNC:
            right = "DCSync (dizin replikasyonu)"
        elif (mask & 0x20) and guid == _KEYCRED:
            right = "Shadow credentials (msDS-KeyCredentialLink yazma)"
        elif (mask & 0x20) and not guid:
            right = "Tüm özelliklere yazma"
        else:
            continue
        name = cache.get(sid)
        if name is None:
            resolved = _resolve_sid(connection, base, sid)
            name = (resolved or {}).get("name") or sid
            cache[sid] = name
        out.append({"principal": name, "sid": sid, "right": right})
    return out


def _risky_ad(connection, base, domain_sid):
    """Dangerous ACLs on privileged accounts, constrained delegation and RBCD — the passive
    equivalent of BloodHound's high-value edges. All read-only LDAP."""
    out = {}
    safe = _safe_sids(domain_sid)
    sd_control = _sd_dacl_control()
    cache = {}
    priv = {}
    try:
        connection.search(base, "(&(objectClass=group)(sAMAccountName=Domain Admins))",
                          attributes=["member"], size_limit=1, time_limit=10)
        if connection.entries:
            for dn in _vals(connection.entries[0], "member"):
                priv[dn] = _cn(dn)
    except Exception:
        pass
    acl_risks = []
    for dn, name in list(priv.items())[:40]:
        for risk in _account_acl_risks(connection, dn, base, safe, sd_control, cache):
            acl_risks.append({"account": name, **risk})
    if acl_risks:
        out["privileged_acl_risks"] = acl_risks[:100]
    deleg = []
    try:
        connection.search(base, "(msDS-AllowedToDelegateTo=*)",
                          attributes=["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"],
                          size_limit=500, time_limit=15)
        for e in connection.entries:
            uac = _as_int(e, "userAccountControl") or 0
            deleg.append({"account": _val(e, "sAMAccountName"),
                          "protocol_transition": bool(uac & 0x1000000),
                          "targets": _vals(e, "msDS-AllowedToDelegateTo")[:20]})
    except Exception:
        pass
    if deleg:
        out["constrained_delegation"] = deleg[:100]
    rbcd = []
    try:
        connection.search(base, "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                          attributes=["sAMAccountName"], size_limit=500, time_limit=15)
        rbcd = sorted(_val(e, "sAMAccountName") for e in connection.entries if _val(e, "sAMAccountName"))
    except Exception:
        pass
    if rbcd:
        out["rbcd_configured"] = rbcd[:100]
    return out


def _cleartext_bind(dc, pinned_ip, username, domain, password):
    """Does the DC accept a SIMPLE bind over cleartext LDAP/389 (no TLS)? If yes, LDAP
    signing/channel-binding is not enforced -> credentials cross the wire in the clear and
    the DC is exposed to NTLM-relay-to-LDAP. Uses the supplied test account only."""
    try:
        from ldap3 import Server, Connection, SIMPLE, NONE
    except Exception:
        return None
    host = pinned_ip or dc
    upn = username if ("@" in username or "\\" in username) else f"{username}@{domain}"
    try:
        server = Server(host, port=389, use_ssl=False, get_info=NONE, connect_timeout=5)
        conn = Connection(server, user=upn, password=password,
                          authentication=SIMPLE, receive_timeout=8)
        ok = bool(conn.bind())
        try:
            conn.unbind()
        except Exception:
            pass
        return ok
    except Exception:
        return None


# Transport ladder: most secure first. Real DCs very often present a self-signed
# LDAPS certificate (or do not publish 636 at all), so strict validation alone
# fails with LDAPSocketOpenError. We degrade gracefully — encrypted-but-unvalidated
# LDAPS, then StartTLS on 389 — and only use plaintext LDAP when the operator opts
# in (it exposes the test-account credential on the wire). Every result records
# which transport succeeded and a security note for the analyst.
TRANSPORTS = (
    ("ldaps_strict", "LDAPS 636 (sertifika doğrulandı)"),
    ("ldaps_insecure", "LDAPS 636 (sertifika DOĞRULANMADI)"),
    ("starttls", "StartTLS 389 (sertifika doğrulanmadı)"),
)
PLAINTEXT = ("plaintext", "Düz metin LDAP 389 (ŞİFRELENMEMİŞ — opt-in)")


def _open(dc, pinned_ip, username, password, mode):
    """Return a bound, read-only ldap3 Connection for the given transport, or raise."""
    from ldap3 import NONE, Connection, Server, Tls
    host = pinned_ip or dc
    common = dict(user=username, password=password, receive_timeout=10,
                  raise_exceptions=True, auto_referrals=False, read_only=True)
    if mode == "ldaps_strict":
        # Bind to the route-checked numeric address; the cert must still name the DC.
        tls = Tls(validate=ssl.CERT_REQUIRED, valid_names=[dc],
                  sni=dc if pinned_ip and pinned_ip != dc else None)
        server = Server(host, port=636, use_ssl=True, get_info=NONE, tls=tls, connect_timeout=5)
        return Connection(server, auto_bind=True, **common)
    if mode == "ldaps_insecure":
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(host, port=636, use_ssl=True, get_info=NONE, tls=tls, connect_timeout=5)
        return Connection(server, auto_bind=True, **common)
    if mode == "starttls":
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(host, port=389, use_ssl=False, get_info=NONE, tls=tls, connect_timeout=5)
        conn = Connection(server, auto_bind=False, **common)
        conn.open(); conn.start_tls(); conn.bind()
        return conn
    server = Server(host, port=389, use_ssl=False, get_info=NONE, connect_timeout=5)
    return Connection(server, auto_bind=True, **common)


def _names(connection, attr="sAMAccountName", cap=300):
    """Collect an attribute's values from the last search, capped and sorted."""
    out = []
    for entry in connection.entries:
        try:
            value = entry[attr].value if attr in entry else None
        except Exception:
            value = None
        if value:
            out.append(str(value))
    return sorted(set(out))[:cap]


def _member_of(connection, base, username):
    """Groups the supplied test account belongs to (its own memberOf) + displayName."""
    sam = str(username or "").split("\\")[-1].split("@")[0].strip()
    if not sam:
        return None
    safe = "".join(ch for ch in sam if ch.isalnum() or ch in "._- ")
    if not safe:
        return None
    try:
        connection.search(base, f"(|(sAMAccountName={safe})(userPrincipalName={safe}@*))",
                          attributes=["memberOf", "displayName", "sAMAccountName"],
                          size_limit=1, time_limit=10)  # ldap3 default scope is SUBTREE
        if not connection.entries:
            return {"account": sam, "groups": [], "note": "hesap dizinde bulunamadı"}
        entry = connection.entries[0]
        groups = []
        try:
            raw = entry["memberOf"].values if "memberOf" in entry else []
        except Exception:
            raw = []
        for dn in raw:
            cn = str(dn).split(",", 1)[0]
            groups.append(cn[3:] if cn.lower().startswith("cn=") else cn)
        display = ""
        try:
            display = str(entry["displayName"].value) if "displayName" in entry else ""
        except Exception:
            display = ""
        return {"account": sam, "display_name": display, "groups": sorted(set(groups))[:100]}
    except Exception:
        return None


def _collect(connection, base, domain, dc, username=""):
    from ldap3 import BASE
    outcome = {}
    samples = {}
    root_data = {}
    connection.search('', '(objectClass=*)', search_scope=BASE,
                      attributes=['rootDomainNamingContext', 'configurationNamingContext',
                                  'dnsHostName', 'domainFunctionality', 'forestFunctionality'],
                      size_limit=1, time_limit=5)
    if connection.entries:
        entry = connection.entries[0]
        for field in ('rootDomainNamingContext', 'configurationNamingContext', 'dnsHostName',
                      'domainFunctionality', 'forestFunctionality'):
            value = entry[field].value if field in entry else None
            root_data[field] = str(value) if value is not None else None
    # Capture NAMES (not just counts): user sAMAccountNames, group names, computer names.
    for label, query, attr in (
        ("users", "(&(objectCategory=person)(objectClass=user))", "sAMAccountName"),
        ("groups", "(objectClass=group)", "sAMAccountName"),
        ("computers", "(objectCategory=computer)", "dNSHostName"),
    ):
        want = ["sAMAccountName", "dNSHostName"] if label == "computers" else [attr]
        connection.search(base, query, attributes=want, size_limit=1000, time_limit=10)
        outcome[label] = {"observed_count": len(connection.entries), "truncated_at": 1000}
        names = _names(connection, attr)
        if label == "computers" and not names:   # fall back to the flat computer name
            names = _names(connection, "sAMAccountName")
            names = [n[:-1] if n.endswith("$") else n for n in names]
        samples[label] = names
    policy, maq, domain_sid = _password_policy(connection, base)
    admins = _domain_admins(connection, base, domain_sid)
    membership = _member_of(connection, base, username)
    deep = _deep_enum(connection, base)
    adcs = _adcs(connection, root_data.get("configurationNamingContext"), domain_sid)
    gpo_ou = _gpo_ou(connection, base)
    risky = _risky_ad(connection, base, domain_sid)
    result = {"status": "ok", "domain": domain, "dc": dc, "root_dse": root_data,
              "inventory": outcome,
              "user_names": samples.get("users", []), "group_names": samples.get("groups", []),
              "computer_names": samples.get("computers", [])}
    if policy:
        result["password_policy"] = policy
    if maq is not None:
        result["machine_account_quota"] = maq
    if admins:
        result["domain_admins"] = admins
    if membership:
        result["test_account_membership"] = membership
    result.update({k: v for k, v in deep.items() if v})
    if adcs:
        result["adcs"] = adcs
    result.update({k: v for k, v in gpo_ou.items() if v})
    result.update({k: v for k, v in risky.items() if v})
    return result


def inspect(dc: str, domain: str, username: str, password: str,
            pinned_ip: str | None = None, allow_plaintext: bool = False) -> dict:
    try:
        import ldap3  # noqa: F401  (probe availability early)
    except ImportError:
        return {"status": "missing_tool", "reason": "ldap3 kurulu degil"}
    if not all((dc, domain, username, password)):
        return {"status": "skipped", "reason": "DC, domain veya test hesabi yok"}
    base = ",".join("DC=" + label for label in domain.lower().split(".") if label)
    if not base or any(not label.replace("-", "").isalnum() for label in domain.split(".")):
        return {"status": "error", "reason": "Gecersiz domain adi"}
    modes = list(TRANSPORTS) + ([PLAINTEXT] if allow_plaintext else [])
    last_reason = ""
    for mode, note in modes:
        try:
            connection = _open(dc, pinned_ip, username, password, mode)
        except Exception as exc:  # transport not available → try the next, less strict one
            last_reason = f"{type(exc).__name__}"
            continue
        try:
            result = _collect(connection, base, domain, dc, username)
        except Exception as exc:
            last_reason = f"{type(exc).__name__}"
            try: connection.unbind()
            except Exception: pass
            continue
        try: connection.unbind()
        except Exception: pass
        result["transport"] = mode
        result["source"] = note + " · salt okunur test hesabı"
        if mode != "ldaps_strict":
            result["security_warning"] = note
        cleartext = _cleartext_bind(dc, pinned_ip, username, domain, password)
        if cleartext is not None:
            result["ldap_cleartext_bind"] = cleartext
        try:
            import sysvol_probe
            sysvol = sysvol_probe.crawl(dc, domain, username, password, pinned_ip)
            if isinstance(sysvol, dict) and sysvol.get("status") == "ok":
                result["sysvol"] = sysvol
        except Exception:
            pass
        return result
    return {"status": "error", "domain": domain, "dc": dc,
            "reason": (f"LDAP baglantisi kurulamadi (denenen: {', '.join(m for m, _ in modes)}); "
                       f"son hata: {last_reason or 'bilinmiyor'}. DC'de LDAPS/636 sertifikasi yoksa "
                       "StartTLS/389 denenir; sifrelenmemis LDAP icin ad_allow_plaintext acin.")}
