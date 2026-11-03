# Rule-Based Intrusion Detection System
Classical AI (Unit IV): propositional/first-order rules + **forward** and **backward chaining**.
No machine learning, no generative AI, no training data. Python 3.9+, standard library only.

## Quick start
```bash
python main.py generate                                   # writes data/sample_logs.csv
python main.py detect data/sample_logs.csv                # forward chaining: all alerts + proofs
python main.py query  data/sample_logs.csv "is_intrusion(carol)"   # backward chaining
python main.py query  data/sample_logs.csv "brute_force(X)"        # capitalised arg = variable
python main.py shell  data/sample_logs.csv                # interactive analyst console
python -m unittest discover -s tests -v                   # 6 tests
```

## Pipeline (matches the architecture slide)
`CSV logs -> fact extractor (ids/logs.py) -> working memory -> forward chaining (ids/engine.py) -> alerts`
and `analyst query -> backward chaining prover -> proof tree`.

| Log event | Facts produced |
|---|---|
| LOGIN_FAILED | `failed_login(IP, U)` |
| LOGIN_SUCCESS | `successful_login(IP, U)`, `login(U)` |
| CONNECTION | `connection_attempt(IP, Port)` |
| PRIV_CHANGE | `privilege_change(U, Role)` |

## Knowledge base (ids/rules.py)
| Rule | IF ... THEN |
|---|---|
| R1 | >=5 `failed_login(IP,_)` within 60s -> `brute_force(IP)` |
| R2 | `brute_force(IP)` + later `successful_login(IP,U)` (<=300s) -> `account_compromised(U)` |
| R3 | >20 `connection_attempt(IP,_)` within 10s -> `port_scan(IP)` |
| R4 | `login(U)` + `privilege_change(U,'admin')` within 5s -> `privilege_escalation(U)` |
| R5a/R5b | `account_compromised(U)` OR `privilege_escalation(U)` -> `is_intrusion(U)` (OR = two rules) |

Deviation from the slide: R2 adds a 300s window so an old brute force cannot "compromise" a login days later. Change it in `rules.py`.

## How the engine works
- **Forward chaining**: repeatedly applies every rule to working memory until a fixed point (no new facts). Each derived fact stores its proof tree.
- **Backward chaining**: starts from a goal, finds rules whose head matches, recursively proves each premise, bottoming out in raw log facts. It never reads forward-chaining results. Cycle guard included.
- Both share one body solver (variable unification, sliding-window `Burst`, `Within` temporal constraint).
- Test `test_forward_and_backward_agree` checks the two modes derive identical conclusions.

## Dataset
`generate` makes 99 synthetic rows: normal traffic, 4 attacks (brute force + compromise of carol, brute force that fails, port scan, privilege escalation by dave) and benign near-misses that must not alert (3 failures, 5 slow failures, 15 connections, admin change hours after login).

## Add your own rule
Append a `Rule(...)` to `RULES` in `ids/rules.py`; no engine change needed.
