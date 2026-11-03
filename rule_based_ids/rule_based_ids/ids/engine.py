"""Symbolic inference engine: forward chaining + backward chaining.

Pure standard library. No ML, no statistics, no GenAI.

Vocabulary
----------
Fact      pred(args) observed/derived at a time (seconds).
Var       a logic variable (names starting with "_" are anonymous wildcards).
Atom      body condition  pred(args)   - matched against facts, or proved recursively.
Burst     body condition  >= N facts matching pred(args) inside a sliding window.
Within    temporal constraint between two labelled atoms (0 <= t2 - t1 <= window).
Rule      head <- body   (a Horn clause with temporal/aggregate conditions).

Both inference modes share one body-solver; they differ only in where atoms come
from: forward chaining reads working memory, backward chaining recursively proves
sub-goals starting from the raw log facts only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional


# ----------------------------------------------------------------- terms ----
class Var:
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name

    @property
    def anonymous(self) -> bool:
        return self.name.startswith("_")

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return isinstance(other, Var) and other.name == self.name

    def __hash__(self):
        return hash(("Var", self.name))


def V(name: str) -> Var:
    return Var(name)


def fmt_time(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")


def fmt_args(args) -> str:
    return ", ".join("_" if a is None else str(a) for a in args)


@dataclass(frozen=True)
class Fact:
    pred: str
    args: tuple
    time: float

    def __str__(self):
        return f"{self.pred}({fmt_args(self.args)})@{fmt_time(self.time)}"

    def short(self):
        return f"{self.pred}({fmt_args(self.args)})"


# ------------------------------------------------------------ conditions ----
@dataclass
class Atom:
    pred: str
    args: tuple
    label: Optional[str] = None


@dataclass
class Burst:
    pred: str
    args: tuple
    count: int
    window: float


@dataclass
class Within:
    first: str
    second: str
    window: float


@dataclass
class Rule:
    id: str
    head: Atom
    body: list
    description: str
    severity: str = "medium"

    def __str__(self):
        parts = []
        for c in self.body:
            if isinstance(c, Atom):
                lab = f"[{c.label}] " if c.label else ""
                parts.append(f"{lab}{c.pred}({fmt_vars(c.args)})")
            elif isinstance(c, Burst):
                parts.append(f">={c.count}x {c.pred}({fmt_vars(c.args)}) within {c.window:g}s")
            else:
                parts.append(f"{c.second} within {c.window:g}s after {c.first}")
        return f"{self.id}: {' AND '.join(parts)}  =>  {self.head.pred}({fmt_vars(self.head.args)})"


def fmt_vars(args) -> str:
    return ", ".join(repr(a) if isinstance(a, Var) else repr(a) for a in args)


# ------------------------------------------------------------ proof tree ----
@dataclass
class Node:
    text: str
    kind: str                     # "fact" | "derived" | "aggregate"
    time: float
    rule: Optional[str] = None
    children: list = field(default_factory=list)


# ----------------------------------------------------------- unification ----
def unify(pattern: tuple, values: tuple, b: dict) -> Optional[dict]:
    """Match a pattern (constants + Vars) against ground values under bindings b."""
    if len(pattern) != len(values):
        return None
    nb = dict(b)
    for p, v in zip(pattern, values):
        if isinstance(p, Var):
            if p.anonymous:
                continue
            if p.name in nb:
                if nb[p.name] != v:
                    return None
            else:
                nb[p.name] = v
        elif p != v:
            return None
    return nb


def ground_pattern(args: tuple, b: dict) -> tuple:
    """Instantiate args with bindings; unbound / anonymous vars become None (wildcard)."""
    out = []
    for a in args:
        if isinstance(a, Var):
            out.append(None if a.anonymous or a.name not in b else b[a.name])
        else:
            out.append(a)
    return tuple(out)


def match_pattern(pattern: tuple, args: tuple) -> bool:
    return len(pattern) == len(args) and all(p is None or p == a for p, a in zip(pattern, args))


def unify_head(head_args: tuple, pattern: tuple) -> Optional[dict]:
    b: dict = {}
    for h, p in zip(head_args, pattern):
        if p is None:
            continue
        if isinstance(h, Var):
            if b.get(h.name, p) != p:
                return None
            b[h.name] = p
        elif h != p:
            return None
    return b


def subst(args: tuple, b: dict) -> tuple:
    return tuple(b[a.name] if isinstance(a, Var) else a for a in args)


# ----------------------------------------------------------- body solver ----
def solve_burst(c: Burst, b: dict, facts) -> Iterator[tuple]:
    groups: dict = {}
    for f in facts:
        nb = unify(c.args, f.args, b)
        if nb is None:
            continue
        groups.setdefault(tuple(sorted(nb.items())), (nb, []))[1].append(f)
    for nb, fs in groups.values():
        fs.sort(key=lambda f: f.time)
        for i in range(len(fs) - c.count + 1):
            w = fs[i:i + c.count]
            if w[-1].time - w[0].time <= c.window:
                yield nb, w
                break                      # first window that satisfies the rule


def solve_body(body, i, b, nodes, times, ctx):
    """Yield (bindings, supporting nodes, label->time) for every way to satisfy body[i:]."""
    if i == len(body):
        yield b, nodes, times
        return
    c = body[i]
    if isinstance(c, Atom):
        for args, node in ctx.atoms(c.pred, ground_pattern(c.args, b)):
            nb = unify(c.args, args, b)
            if nb is None:
                continue
            nt = dict(times)
            if c.label:
                nt[c.label] = node.time
            yield from solve_body(body, i + 1, nb, nodes + [node], nt, ctx)
    elif isinstance(c, Burst):
        for nb, w in solve_burst(c, b, ctx.events(c.pred)):
            span = w[-1].time - w[0].time
            text = (f"{len(w)}x {c.pred}({fmt_args(ground_pattern(c.args, nb))}) "
                    f"within {span:g}s (limit {c.window:g}s)")
            node = Node(text, "aggregate", w[-1].time,
                        children=[Node(str(f), "fact", f.time) for f in w])
            yield from solve_body(body, i + 1, nb, nodes + [node], times, ctx)
    else:  # Within
        d = times[c.second] - times[c.first]
        if 0 <= d <= c.window:
            yield from solve_body(body, i + 1, b, nodes, times, ctx)


def _derived_node(rule: Rule, args: tuple, nodes: list) -> Node:
    t = max(n.time for n in nodes)
    return Node(f"{rule.head.pred}({fmt_args(args)})@{fmt_time(t)}", "derived", t,
                rule=rule.id, children=nodes)


# ------------------------------------------------------- forward chaining ----
@dataclass
class ForwardResult:
    facts: list                   # base + derived Facts
    derived: list                 # (round, Rule, Fact, Node) in derivation order
    rounds: int


class _ForwardCtx:
    def __init__(self, base_by_pred):
        self.by_pred = {p: list(v) for p, v in base_by_pred.items()}  # pred -> [(Fact, Node)]
        self.base = base_by_pred

    def atoms(self, pred, pattern):
        for f, node in list(self.by_pred.get(pred, [])):
            if match_pattern(pattern, f.args):
                yield f.args, node

    def events(self, pred):
        return [f for f, _ in self.base.get(pred, [])]


def forward_chain(base_facts: list, rules: list) -> ForwardResult:
    base_by_pred: dict = {}
    for f in base_facts:
        base_by_pred.setdefault(f.pred, []).append((f, Node(str(f), "fact", f.time)))
    ctx = _ForwardCtx(base_by_pred)
    known = {(f.pred, f.args) for f in base_facts}
    derived, rounds, changed = [], 0, True
    while changed:                                  # run until fixed point
        changed = False
        rounds += 1
        for rule in rules:
            for b, nodes, _ in list(solve_body(rule.body, 0, {}, [], {}, ctx)):
                args = subst(rule.head.args, b)
                if (rule.head.pred, args) in known:
                    continue
                node = _derived_node(rule, args, nodes)
                fact = Fact(rule.head.pred, args, node.time)
                known.add((fact.pred, fact.args))
                ctx.by_pred.setdefault(fact.pred, []).append((fact, node))
                derived.append((rounds, rule, fact, node))
                changed = True
    all_facts = list(base_facts) + [d[2] for d in derived]
    return ForwardResult(all_facts, derived, rounds)


# ------------------------------------------------------ backward chaining ----
class Prover:
    """Goal-driven prover. Uses ONLY raw log facts and rules (never forward results)."""

    def __init__(self, base_facts: list, rules: list):
        self.base: dict = {}
        for f in base_facts:
            self.base.setdefault(f.pred, []).append(f)
        self.rules: dict = {}
        for r in rules:
            self.rules.setdefault(r.head.pred, []).append(r)

    def predicates(self):
        return set(self.base) | set(self.rules)

    def ask(self, pred: str, pattern: tuple) -> list:
        """All provable instances of pred(pattern); None in pattern = unknown. -> [(args, Node)]"""
        return list(self._prove(pred, tuple(pattern), ()))

    def _prove(self, pred, pattern, stack):
        key = (pred, pattern)
        if key in stack:                            # cycle guard
            return
        for f in self.base.get(pred, []):
            if match_pattern(pattern, f.args):
                yield f.args, Node(str(f), "fact", f.time)
        seen = set()
        ctx = _BackwardCtx(self, stack + (key,))
        for rule in self.rules.get(pred, []):
            b0 = unify_head(rule.head.args, pattern)
            if b0 is None:
                continue
            for b, nodes, _ in solve_body(rule.body, 0, b0, [], {}, ctx):
                args = subst(rule.head.args, b)
                if args in seen:
                    continue
                seen.add(args)
                yield args, _derived_node(rule, args, nodes)


class _BackwardCtx:
    def __init__(self, prover: Prover, stack: tuple):
        self.prover, self.stack = prover, stack

    def atoms(self, pred, pattern):
        return self.prover._prove(pred, pattern, self.stack)

    def events(self, pred):
        return self.prover.base.get(pred, [])
