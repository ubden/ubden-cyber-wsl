"""Bounded, read-only directory inventory with an explicitly supplied test user.

Beyond object counts, this reads the domain password policy, the machine
account quota, and Domain Admins membership — all standard read-only LDAP reads
that a normal domain user can perform. They feed *draft* findings (weak password
policy, machine-join by any user, excessive domain admins); the analyst confirms
impact before any becomes verified.
"""
from __future__ import annotations

import ssl


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
                      attributes=['rootDomainNamingContext', 'dnsHostName',
                                  'domainFunctionality', 'forestFunctionality'],
                      size_limit=1, time_limit=5)
    if connection.entries:
        entry = connection.entries[0]
        for field in ('rootDomainNamingContext', 'dnsHostName',
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
        return result
    return {"status": "error", "domain": domain, "dc": dc,
            "reason": (f"LDAP baglantisi kurulamadi (denenen: {', '.join(m for m, _ in modes)}); "
                       f"son hata: {last_reason or 'bilinmiyor'}. DC'de LDAPS/636 sertifikasi yoksa "
                       "StartTLS/389 denenir; sifrelenmemis LDAP icin ad_allow_plaintext acin.")}
