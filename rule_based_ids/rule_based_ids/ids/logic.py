"""Core logic primitives for the rule-based IDS.

Everything here is classical symbolic AI: facts are ground predicates,
rules are Horn-style IF-THEN clauses with variables (first-order), and
variables are bound by unification against facts in working memory.

No machine learning, no statistics, no generative AI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterator, List, Optional, Tuple

Bindings = Dict[str, str]


def is_var(x) -> bool:
    """Variables are strings that start with '?', e.g. '?ip'."""
    return isinstance(x, str) and x.startswith("?")


def fmt_time(t: Optional[float]) -> str:
    if t is None:
        return "-"
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")


@dataclass(frozen=True)
class Fact:
    """A ground fact such as failed_login(203.0.113.7, root) with a timestamp."""

    pred: str
    args: Tuple[str, ...]
    t: Optional[float] = None

    def key(self) -> Tuple[str, Tuple[str, ...]]:
        return (self.pred, self.args)

    def __str__(self) -> str:
        return f"{self.pred}({', '.join(self.args)})"


@dataclass
class Proof:
    """A proof tree node.  rule=None means the fact was asserted from the log."""

    fact: Fact
    rule: Optional[str] = None
    children: List["Proof"] = field(default_factory=list)


# --------------------------------------------------------------------------
# Unification helpers
# --------------------------------------------------------------------------
def match_args(pattern: Tuple[str, ...], args: Tuple[str, ...], b: Bindings) -> Optional[Bindings]:
    """Unify a pattern (may hold variables) with ground args under bindings b."""
    if len(pattern) != len(args):
        return None
    out = dict(b)
    for p, a in zip(pattern, args):
        if is_var(p):
            if p in out:
                if out[p] != a:
                    return None
            else:
                out[p] = a
        elif p != a:
            return None
    return out


def substitute(args: Tuple[str, ...], b: Bindings) -> Tuple[str, ...]:
    return tuple(b.get(a, a) if is_var(a) else a for a in args)


# A lookup answers "which facts match this pattern?".  Forward chaining wires it
# to working memory; backward chaining wires it to the recursive prover.
Lookup = Callable[[str, Tuple[str, ...], Bindings], List[Tuple[Bindings, Proof]]]


# --------------------------------------------------------------------------
# Premises (the IF part of a rule)
# --------------------------------------------------------------------------
class Atom:
    """A plain predicate pattern, e.g. brute_force(?ip)."""

    def __init__(self, pred: str, *args: str):
        self.pred = pred
        self.args = tuple(args)

    def solve(self, lookup: Lookup, b: Bindings) -> Iterator[Tuple[Bindings, List[Proof]]]:
        for b2, proof in lookup(self.pred, self.args, b):
            yield b2, [proof]

    def __str__(self) -> str:
        return f"{self.pred}({', '.join(self.args)})"


class CountWithin:
    """At least n facts matching a pattern, grouped by some variables, inside a time window.

    Example: 5 failed_login(?ip, ?u) per ?ip within 60 seconds.
    Variables not listed in group_by are free (they may differ between the facts).
    """

    def __init__(self, pred: str, args: Tuple[str, ...], group_by: Tuple[str, ...], n: int, window: float):
        self.pred, self.args = pred, tuple(args)
        self.group_by, self.n, self.window = tuple(group_by), n, window

    def solve(self, lookup: Lookup, b: Bindings) -> Iterator[Tuple[Bindings, List[Proof]]]:
        groups: Dict[tuple, List[Proof]] = {}
        for b2, proof in lookup(self.pred, self.args, b):
            groups.setdefault(tuple(b2.get(v) for v in self.group_by), []).append(proof)
        for key, proofs in groups.items():
            proofs.sort(key=lambda p: p.fact.t)
            for i in range(len(proofs) - self.n + 1):
                if proofs[i + self.n - 1].fact.t - proofs[i].fact.t <= self.window:
                    # evidence = every matching fact inside the window that starts at i
                    evidence = [p for p in proofs[i:] if p.fact.t - proofs[i].fact.t <= self.window]
                    nb = dict(b)
                    nb.update(zip(self.group_by, key))
                    yield nb, evidence
                    break

    def __str__(self) -> str:
        grp = ", ".join(self.group_by)
        return (f">= {self.n} x {self.pred}({', '.join(self.args)}) "
                f"per {grp} within {self.window:g}s")


class Sequence:
    """Atom A followed by atom B, at most `within` seconds later."""

    def __init__(self, first: Atom, then: Atom, within: float):
        self.first, self.then, self.within = first, then, within

    def solve(self, lookup: Lookup, b: Bindings) -> Iterator[Tuple[Bindings, List[Proof]]]:
        for b1, p1 in lookup(self.first.pred, self.first.args, b):
            for b2, p2 in lookup(self.then.pred, self.then.args, b1):
                dt = p2.fact.t - p1.fact.t
                if 0 <= dt <= self.within:
                    yield b2, [p1, p2]

    def __str__(self) -> str:
        return f"{self.first} then {self.then} within {self.within:g}s"


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
class Rule:
    def __init__(self, rid: str, name: str, head: Atom, body: list, severity: str, detects: str):
        self.id, self.name, self.head, self.body = rid, name, head, body
        self.severity, self.detects = severity, detects

    def solve(self, lookup: Lookup, b: Optional[Bindings] = None):
        """Yield (bindings, supporting proofs) for every way the body is satisfied."""

        def rec(i: int, bnd: Bindings, supports: List[Proof]):
            if i == len(self.body):
                yield bnd, supports
                return
            for b2, nodes in self.body[i].solve(lookup, bnd):
                yield from rec(i + 1, b2, supports + nodes)

        yield from rec(0, dict(b or {}), [])

    def head_args(self, b: Bindings) -> Optional[Tuple[str, ...]]:
        args = substitute(self.head.args, b)
        return None if any(is_var(a) for a in args) else args

    def if_then(self) -> str:
        return "IF " + " AND ".join(str(p) for p in self.body) + f" THEN {self.head}"
