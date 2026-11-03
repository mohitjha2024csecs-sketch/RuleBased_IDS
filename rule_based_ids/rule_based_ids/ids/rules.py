"""Knowledge base: hand-authored attack-pattern rules (R1-R5 from the first review)."""
from .engine import Atom, Burst, Rule, Within, V

IP, U, _ = V("IP"), V("U"), V("_")

RULES = [
    Rule("R1",
         Atom("brute_force", (IP,)),
         [Burst("failed_login", (IP, V("_u")), count=5, window=60)],
         "5 failed logins from one IP within 60s", "high"),
    Rule("R2",
         Atom("account_compromised", (U,)),
         [Atom("brute_force", (IP,), label="bf"),
          Atom("successful_login", (IP, U), label="ok"),
          Within("bf", "ok", 300)],
         "Successful login from an IP that just brute-forced (within 5 min)", "critical"),
    Rule("R3",
         Atom("port_scan", (IP,)),
         [Burst("connection_attempt", (IP, V("_p")), count=21, window=10)],
         ">20 connection attempts from one IP within 10s", "medium"),
    Rule("R4",
         Atom("privilege_escalation", (U,)),
         [Atom("login", (U,), label="login"),
          Atom("privilege_change", (U, "admin"), label="priv"),
          Within("login", "priv", 5)],
         "Login followed by promotion to admin within 5s", "critical"),
    Rule("R5a",
         Atom("is_intrusion", (U,)),
         [Atom("account_compromised", (U,))],
         "Compromised account is an intrusion", "critical"),
    Rule("R5b",
         Atom("is_intrusion", (U,)),
         [Atom("privilege_escalation", (U,))],
         "Privilege escalation is an intrusion", "critical"),
]

RULES_BY_ID = {r.id: r for r in RULES}
