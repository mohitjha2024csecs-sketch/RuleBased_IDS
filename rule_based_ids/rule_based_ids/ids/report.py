"""Human-readable output: proof trees and alert reports."""
from .engine import Node


def render_tree(node: Node, prefix: str = "", is_last: bool = True, root: bool = True) -> str:
    tag = f"  [{node.rule}]" if node.rule else ""
    if root:
        lines, child_prefix = [node.text + tag], ""
    else:
        lines = [prefix + ("└─ " if is_last else "├─ ") + node.text + tag]
        child_prefix = prefix + ("   " if is_last else "│  ")
    kids = node.children
    if node.kind == "aggregate" and len(kids) > 4:      # keep long bursts readable
        kids = kids[:2] + [Node(f"... {len(kids) - 3} more ...", "fact", 0)] + kids[-1:]
    for i, k in enumerate(kids):
        lines.append(render_tree(k, child_prefix, i == len(kids) - 1, False))
    return "\n".join(lines)


def alert_report(result, rules_by_id) -> str:
    from .engine import fmt_time
    out = []
    ordered = sorted(result.derived, key=lambda d: (d[3].time, d[0]))
    for _, rule, fact, node in ordered:
        out.append(f"[{rules_by_id[rule.id].severity.upper():8}] {fmt_time(fact.time)}  "
                   f"{fact.short()}   ({rule.id}: {rule.description})")
        out.append(render_tree(node))
        out.append("")
    return "\n".join(out)
