#!/usr/bin/env python3
"""Rule-Based IDS - command line interface.

  python main.py generate [--out data/sample_logs.csv]
  python main.py detect   data/sample_logs.csv            # forward chaining
  python main.py query    data/sample_logs.csv "is_intrusion(carol)"   # backward chaining
  python main.py shell    data/sample_logs.csv            # interactive analyst console
"""
import argparse
import re
import sys

from ids.engine import Prover, forward_chain, fmt_args
from ids.logs import generate, load_facts
from ids.report import alert_report, render_tree
from ids.rules import RULES, RULES_BY_ID


def parse_goal(text: str):
    m = re.fullmatch(r"\s*(\w+)\s*\((.*)\)\s*", text)
    if not m:
        raise ValueError("goal must look like predicate(arg, ...), e.g. is_intrusion(carol)")
    pred, raw = m.group(1), m.group(2)
    pattern = []
    for tok in (t.strip().strip("'\"") for t in raw.split(",") if t.strip()):
        if tok[0].isupper() or tok[0] == "_":
            pattern.append(None)                      # variable -> "find all"
        elif tok.isdigit():
            pattern.append(int(tok))
        else:
            pattern.append(tok)
    return pred, tuple(pattern)


def cmd_detect(facts):
    res = forward_chain(facts, RULES)
    print(f"Loaded {len(facts)} base facts; fixed point after {res.rounds} rounds; "
          f"{len(res.derived)} facts derived.\n")
    print(alert_report(res, RULES_BY_ID))
    return res


def cmd_query(facts, goal_text):
    pred, pattern = parse_goal(goal_text)
    prover = Prover(facts, RULES)
    if pred not in prover.predicates():
        print(f"Unknown predicate '{pred}'. Known: {', '.join(sorted(prover.predicates()))}")
        return
    answers = prover.ask(pred, pattern)
    if not answers:
        rules = [r.id for r in RULES if r.head.pred == pred]
        why = f"rules tried: {', '.join(rules)}" if rules else "no log facts match"
        print(f"{pred}({fmt_args(pattern)})?  NO - no proof found ({why}).")
        return
    print(f"{pred}({fmt_args(pattern)})?  YES - {len(answers)} proof(s)\n")
    for args, node in answers:
        print(f"{pred}({fmt_args(args)})")
        print(render_tree(node), end="\n\n")


HELP = """commands:
  alerts                 run forward chaining over the log, show all alerts
  query <goal>           backward chaining, e.g.  query is_intrusion(carol)
                         use a Capitalised arg as a variable: query brute_force(X)
  facts [predicate]      list base facts (optionally one predicate)
  rules                  show the knowledge base
  help | quit"""


def cmd_shell(facts):
    print(f"Rule-Based IDS console - {len(facts)} facts loaded. Type 'help'.")
    while True:
        try:
            line = input("ids> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        try:
            if cmd in ("quit", "exit"):
                return
            elif cmd == "help":
                print(HELP)
            elif cmd == "alerts":
                cmd_detect(facts)
            elif cmd == "query":
                cmd_query(facts, rest)
            elif cmd == "rules":
                print("\n".join(str(r) for r in RULES))
            elif cmd == "facts":
                for f in facts:
                    if not rest or f.pred == rest.strip():
                        print(f)
            else:
                print("unknown command; type 'help'")
        except ValueError as e:
            print(f"error: {e}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", default="data/sample_logs.csv")
    g.add_argument("--seed", type=int, default=7)
    for name in ("detect", "shell"):
        sub.add_parser(name).add_argument("logfile")
    q = sub.add_parser("query")
    q.add_argument("logfile")
    q.add_argument("goal")
    a = ap.parse_args(argv)

    if a.cmd == "generate":
        print(f"wrote {generate(a.out, a.seed)} log rows to {a.out}")
        return
    facts = load_facts(a.logfile)
    {"detect": lambda: cmd_detect(facts),
     "query": lambda: cmd_query(facts, a.goal),
     "shell": lambda: cmd_shell(facts)}[a.cmd]()


if __name__ == "__main__":
    sys.exit(main())
