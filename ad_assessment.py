"""Bounded, read-only directory inventory with an explicitly supplied test user."""
from __future__ import annotations

import ssl


def inspect(dc: str, domain: str, username: str, password: str,
            pinned_ip: str | None = None) -> dict:
    try:
        from ldap3 import BASE, NONE, Connection, Server, Tls
    except ImportError:
        return {"status": "missing_tool", "reason": "ldap3 kurulu degil"}
    if not all((dc, domain, username, password)):
        return {"status": "skipped", "reason": "DC, domain veya test hesabi yok"}
    base = ",".join("DC=" + label for label in domain.lower().split(".") if label)
    if not base or any(not label.replace("-", "").isalnum() for label in domain.split(".")):
        return {"status": "error", "reason": "Gecersiz domain adi"}
    try:
        # Bind to the route-checked numeric address.  The certificate must
        # still identify the operator-supplied DC name.
        tls = Tls(validate=ssl.CERT_REQUIRED, valid_names=[dc],
                  sni=dc if pinned_ip and pinned_ip != dc else None)
        server = Server(pinned_ip or dc, port=636, use_ssl=True, get_info=NONE,
                        tls=tls, connect_timeout=5)
        with Connection(server, user=username, password=password,
                        auto_bind=True, receive_timeout=10, raise_exceptions=True,
                        auto_referrals=False, read_only=True) as connection:
            outcome = {}
            root_data={}
            connection.search('', '(objectClass=*)', search_scope=BASE,
                              attributes=['rootDomainNamingContext','dnsHostName',
                                          'domainFunctionality','forestFunctionality'],
                              size_limit=1,time_limit=5)
            if connection.entries:
                entry=connection.entries[0]
                for field in ('rootDomainNamingContext','dnsHostName',
                              'domainFunctionality','forestFunctionality'):
                    value=entry[field].value if field in entry else None
                    root_data[field]=str(value) if value is not None else None
            for label, query in (
                ("users", "(&(objectCategory=person)(objectClass=user))"),
                ("groups", "(objectClass=group)"),
                ("computers", "(objectCategory=computer)"),
            ):
                connection.search(base, query, attributes=["distinguishedName"],
                                  size_limit=1000, time_limit=10)
                outcome[label] = {"observed_count": len(connection.entries),
                                  "truncated_at": 1000}
            return {"status": "ok", "domain": domain, "dc": dc,
                    "source": "LDAPS read-only test account", "root_dse": root_data,
                    "inventory": outcome}
    except Exception as exc:
        return {"status": "error", "domain": domain, "dc": dc,
                "reason": f"{type(exc).__name__}: LDAPS sorgusu basarisiz"}
