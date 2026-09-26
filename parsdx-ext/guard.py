"""Lockout-aware authentication guard for the PARSDX post-UBDEN offensive chain.

No offensive tool in our stack (NetExec, kerbrute, Impacket) enforces account-lockout
safety. This module is that safety layer: it reads the domain lockout policy over LDAP,
computes a conservative per-principal attempt budget, and gates EVERY authenticated
attempt so we can never lock out a real user. This is the load-bearing control for the
contract's "low-rate, lockout-aware, non-destructive" clause.

Pure logic (policy math + budget enforcement) runs and self-tests with no live DC and no
extra deps. The live LDAP read uses ldap3 only if it is installed.

    python3 guard.py --self-test
    python3 guard.py --policy --dc dc01.corp.local --domain corp.local \
                     --user svc_test --password '***' [--ip 10.0.0.10]
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from dataclasses import dataclass, field

# AD stores lockOutObservationWindow / lockoutDuration as a negative count of
# 100-nanosecond intervals. 1 minute = 60s = 6e10 ns = 6e8 * (100 ns).
_HUNDRED_NS_PER_MINUTE = 600_000_000

# Substrings that mean "an account just got locked / revoked / disabled" in tool output.
# Scanned after every authenticated step; a hit hard-stops the whole run.
LOCKOUT_SIGNALS = (
    "STATUS_ACCOUNT_LOCKED_OUT", "STATUS_ACCOUNT_LOCKED", "KDC_ERR_CLIENT_REVOKED",
    "STATUS_ACCOUNT_DISABLED", "STATUS_ACCOUNT_EXPIRED", "STATUS_PASSWORD_EXPIRED",
    "ACCOUNT HAS BEEN LOCKED", "ACCOUNT LOCKED OUT", "CLIENT'S CREDENTIALS HAVE BEEN REVOKED",
)


def is_lockout_signal(text: str) -> bool:
    """True if tool output indicates an account lockout/revocation/disable."""
    t = (text or "").upper()
    return any(sig in t for sig in LOCKOUT_SIGNALS)


def filetime_interval_to_minutes(value) -> float | None:
    """Convert an AD negative-interval attribute (100-ns units) to minutes.

    Returns None if the value is missing/unparseable. AD uses 0 or the sentinel
    -0x8000000000000000 ('never') for 'not set'.
    """
    if value is None:
        return None
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None
    if raw == 0 or raw == -0x8000000000000000:
        return None
    return abs(raw) / _HUNDRED_NS_PER_MINUTE


@dataclass
class LockoutPolicy:
    """Normalized domain lockout policy."""
    threshold: int                       # bad attempts before lockout; 0 = never locks
    observation_window_min: float | None  # window after which the bad-pw count resets
    duration_min: float | None            # how long an account stays locked
    source: str = "unknown"

    @property
    def locks_out(self) -> bool:
        return self.threshold > 0


def parse_lockout_policy(attrs: dict, source: str = "ldap") -> LockoutPolicy:
    """Build a LockoutPolicy from raw AD domain-root attributes.

    Accepts the attribute names as returned by LDAP: lockoutThreshold,
    lockOutObservationWindow, lockoutDuration (case-insensitive).
    """
    low = {str(k).lower(): v for k, v in attrs.items()}

    def _first(v):
        # ldap3 returns single values or lists depending on config.
        if isinstance(v, (list, tuple)):
            return v[0] if v else None
        return v

    try:
        threshold = int(_first(low.get("lockoutthreshold")) or 0)
    except (TypeError, ValueError):
        threshold = 0
    return LockoutPolicy(
        threshold=threshold,
        observation_window_min=filetime_interval_to_minutes(_first(low.get("lockoutobservationwindow"))),
        duration_min=filetime_interval_to_minutes(_first(low.get("lockoutduration"))),
        source=source,
    )


class LockoutRisk(Exception):
    """Raised when continuing would risk (or has hit) an account lockout."""


@dataclass
class AuthGuard:
    """Gate authenticated attempts so we never reach the lockout threshold.

    Budget per principal, per observation window:
        budget = threshold - safety_margin   (when the domain locks out)
        budget = hard_cap                     (when it does not, stay polite anyway)
    Always clamped by hard_cap when set. Attempts older than the observation
    window are pruned (the bad-password counter has reset by then).
    """
    policy: LockoutPolicy
    safety_margin: int = 1
    hard_cap: int | None = 3
    jitter_seconds: tuple[float, float] = (0.4, 1.6)
    # internal state: principal(lower) -> list of attempt epoch-seconds
    _attempts: dict = field(default_factory=dict)
    _aborted: bool = False

    def budget(self) -> float:
        if self.policy.locks_out:
            b = max(0, self.policy.threshold - self.safety_margin)
        else:
            b = float("inf")
        if self.hard_cap is not None:
            b = min(b, self.hard_cap)
        return b

    def _window_seconds(self) -> float | None:
        w = self.policy.observation_window_min
        return None if w is None else w * 60.0

    def _prune(self, principal: str, now: float) -> None:
        win = self._window_seconds()
        if win is None:
            return  # unknown window -> never reset within a run (most conservative)
        cutoff = now - win
        self._attempts[principal] = [t for t in self._attempts.get(principal, []) if t > cutoff]

    def remaining(self, principal: str, now: float | None = None) -> float:
        now = time.time() if now is None else now
        p = principal.lower()
        self._prune(p, now)
        used = len(self._attempts.get(p, []))
        return self.budget() - used

    def can_attempt(self, principal: str, now: float | None = None) -> bool:
        if self._aborted:
            return False
        return self.remaining(principal, now) >= 1

    def record_attempt(self, principal: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._attempts.setdefault(principal.lower(), []).append(now)

    def note_lockout(self, principal: str) -> None:
        """A live lockout signal (e.g. STATUS_ACCOUNT_LOCKED) -> hard-stop everything."""
        self._aborted = True
        raise LockoutRisk(f"Account lockout observed on '{principal}'. Aborting all auth.")

    def guarded_attempt(self, principal: str, fn, now: float | None = None):
        """Run fn() as one authenticated attempt iff the budget allows it.

        Raises LockoutRisk instead of spending the last safe attempt. Applies jitter
        before the call to avoid hammering the DC.
        """
        if not self.can_attempt(principal, now):
            raise LockoutRisk(
                f"Budget exhausted for '{principal}' "
                f"(threshold={self.policy.threshold}, margin={self.safety_margin}, "
                f"cap={self.hard_cap}, window={self.policy.observation_window_min} min). "
                f"Refusing further attempts."
            )
        lo, hi = self.jitter_seconds
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        self.record_attempt(principal, now)
        return fn()


def read_lockout_policy_ldap(dc, domain, user, password, pinned_ip=None) -> LockoutPolicy:
    """Read the live domain lockout policy over LDAPS (read-only). Needs ldap3."""
    try:
        from ldap3 import BASE, NONE, Connection, Server, Tls
        import ssl
    except ImportError as exc:  # pragma: no cover - env dependent
        raise LockoutRisk("ldap3 not installed; cannot read live lockout policy") from exc
    base = ",".join("DC=" + l for l in domain.lower().split(".") if l)
    tls = Tls(validate=ssl.CERT_REQUIRED, valid_names=[dc])
    server = Server(pinned_ip or dc, port=636, use_ssl=True, get_info=NONE, tls=tls, connect_timeout=5)
    with Connection(server, user=user, password=password, auto_bind=True,
                    read_only=True, receive_timeout=10, raise_exceptions=True) as conn:
        conn.search(base, "(objectClass=domainDNS)", search_scope=BASE,
                    attributes=["lockoutThreshold", "lockOutObservationWindow", "lockoutDuration"],
                    size_limit=1, time_limit=5)
        if not conn.entries:
            raise LockoutRisk("Domain root returned no lockout attributes")
        e = conn.entries[0]
        attrs = {a: e[a].value for a in ("lockoutThreshold", "lockOutObservationWindow", "lockoutDuration") if a in e}
        return parse_lockout_policy(attrs, source=f"ldaps://{dc}")


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if cond:
            ok += 1
        print(f"  [{status}] {name}")
        return cond

    # FILETIME conversion: default AD 30-minute window = -18000000000 (100-ns units).
    check("30 min interval parses", filetime_interval_to_minutes(-18_000_000_000) == 30.0)
    check("10 min interval parses", filetime_interval_to_minutes(-6_000_000_000) == 10.0)
    check("zero -> None (not set)", filetime_interval_to_minutes(0) is None)
    check("never-sentinel -> None", filetime_interval_to_minutes(-0x8000000000000000) is None)

    # Policy parsing from raw AD attrs (threshold 5, 30-min window/duration).
    pol = parse_lockout_policy({
        "lockoutThreshold": 5,
        "lockOutObservationWindow": -18_000_000_000,
        "lockoutDuration": -18_000_000_000,
    })
    check("threshold parsed", pol.threshold == 5)
    check("window minutes parsed", pol.observation_window_min == 30.0)
    check("policy locks out", pol.locks_out is True)

    # Budget = threshold - margin, clamped by hard_cap.
    g = AuthGuard(pol, safety_margin=1, hard_cap=10)
    check("budget = threshold-1 when under cap", g.budget() == 4)
    g_capped = AuthGuard(pol, safety_margin=1, hard_cap=2)
    check("hard_cap clamps budget", g_capped.budget() == 2)

    # Enforcement within a window (deterministic clock via now=).
    g2 = AuthGuard(pol, safety_margin=1, hard_cap=10, jitter_seconds=(0, 0))
    t0 = 1_000_000.0
    allowed = 0
    for _ in range(10):
        if g2.can_attempt("alice", now=t0):
            g2.record_attempt("alice", now=t0)
            allowed += 1
    check("exactly threshold-1 attempts allowed in-window", allowed == 4)
    check("blocked after budget spent", g2.can_attempt("alice", now=t0) is False)

    # Window reset: after the observation window, the counter clears.
    later = t0 + 31 * 60
    check("budget refreshes after observation window", g2.can_attempt("alice", now=later) is True)

    # No-lockout domain (threshold 0) still capped by hard_cap.
    pol0 = parse_lockout_policy({"lockoutThreshold": 0})
    g3 = AuthGuard(pol0, hard_cap=3)
    check("threshold 0 -> not locks_out", pol0.locks_out is False)
    check("threshold 0 still capped by hard_cap", g3.budget() == 3)

    # lockout-signal detection (the kill-switch input)
    check("detects STATUS_ACCOUNT_LOCKED_OUT", is_lockout_signal("SMB ... STATUS_ACCOUNT_LOCKED_OUT"))
    check("detects KDC_ERR_CLIENT_REVOKED", is_lockout_signal("KDC_ERR_CLIENT_REVOKED"))
    check("clean output is not a lockout", not is_lockout_signal("SMB 10.0.0.1 [+] ok (Pwn3d!)"))

    # guarded_attempt refuses past budget and a live lockout aborts everything.
    g4 = AuthGuard(pol, safety_margin=1, hard_cap=2, jitter_seconds=(0, 0))
    calls = 0

    def _fn():
        nonlocal calls
        calls += 1
        return "sent"

    g4.guarded_attempt("bob", _fn, now=t0)
    g4.guarded_attempt("bob", _fn, now=t0)
    refused = False
    try:
        g4.guarded_attempt("bob", _fn, now=t0)
    except LockoutRisk:
        refused = True
    check("guarded_attempt refuses the over-budget call", refused and calls == 2)

    total = 18
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PARSDX lockout-aware auth guard")
    ap.add_argument("--self-test", action="store_true", help="run offline self-tests")
    ap.add_argument("--policy", action="store_true", help="read live lockout policy over LDAPS")
    ap.add_argument("--dc"); ap.add_argument("--domain")
    ap.add_argument("--user"); ap.add_argument("--password")
    ap.add_argument("--ip", default=None)
    ap.add_argument("--margin", type=int, default=1)
    ap.add_argument("--cap", type=int, default=3)
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.policy:
        if not all((args.dc, args.domain, args.user, args.password)):
            ap.error("--policy requires --dc --domain --user --password")
        pol = read_lockout_policy_ldap(args.dc, args.domain, args.user, args.password, args.ip)
        g = AuthGuard(pol, safety_margin=args.margin, hard_cap=args.cap)
        print(f"policy source : {pol.source}")
        print(f"threshold     : {pol.threshold} ({'locks out' if pol.locks_out else 'NEVER locks out'})")
        print(f"obs window    : {pol.observation_window_min} min")
        print(f"lock duration : {pol.duration_min} min")
        print(f"SAFE BUDGET   : {g.budget()} attempt(s) per principal per window "
              f"(margin={args.margin}, cap={args.cap})")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
