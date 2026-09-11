# -*- coding: utf-8 -*-
"""栈上疑似返回地址扫描 → 符号候选调用栈。"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dumptrace.mem_stack import scan_stack_words
from dumptrace.symbolizer import SymbolInfo, symbolize_addresses


DEFAULT_CODE_RANGES: List[Tuple[int, int]] = [
    (0x60000000, 0x62000000),
    (0x00000000, 0x01000000),  # 部分镜像低位映射
]


@dataclass
class CallstackResult:
    ok: bool
    candidates: List[Dict[str, Any]]
    warnings: List[str]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_code_ranges(specs: Sequence[str]) -> List[Tuple[int, int]]:
    """解析 ['0x60000000-0x62000000', ...]。"""
    out: List[Tuple[int, int]] = []
    for s in specs:
        s = s.strip()
        if "-" not in s:
            continue
        a, _, b = s.partition("-")
        try:
            lo = int(a.strip(), 16)
            hi = int(b.strip(), 16)
        except ValueError:
            continue
        if hi >= lo:
            out.append((lo, hi))
    return out or list(DEFAULT_CODE_RANGES)


def build_callstack_candidates(
    stack_data: bytes,
    *,
    stack_start: int,
    axf: Optional[Path],
    addr2line: Optional[Path] = None,
    code_ranges: Optional[Sequence[Tuple[int, int]]] = None,
    max_candidates: int = 40,
) -> CallstackResult:
    ranges = list(code_ranges) if code_ranges else list(DEFAULT_CODE_RANGES)
    hits = scan_stack_words(
        stack_data, stack_start=stack_start, code_ranges=ranges
    )
    if not hits:
        return CallstackResult(
            ok=True,
            candidates=[],
            warnings=["no code-like words found on stack"],
        )

    # 限制数量：靠近栈顶（高地址通常更新）优先 —— 按 stack_addr 降序
    hits = sorted(hits, key=lambda x: x[0], reverse=True)[:max_candidates]

    if axf is None:
        cands = [
            {
                "stack_addr": f"0x{sa:x}",
                "code_addr": f"0x{ca:x}",
                "func": None,
                "file": None,
                "line": None,
                "ok": False,
            }
            for sa, ca in hits
        ]
        return CallstackResult(
            ok=True,
            candidates=cands,
            warnings=["no axf; callstack addresses not symbolized"],
        )

    items = [("stack", f"0x{ca:x}") for _, ca in hits]
    symbols, warns = symbolize_addresses(axf, items, addr2line=addr2line)
    # 按顺序对齐
    cands: List[Dict[str, Any]] = []
    for (sa, ca), sym in zip(hits, symbols):
        cands.append(
            {
                "stack_addr": f"0x{sa:x}",
                "code_addr": f"0x{ca:x}",
                "func": sym.func,
                "file": sym.file,
                "line": sym.line,
                "ok": sym.ok,
            }
        )
    # 只保留成功符号的排在前面展示，但文件里全保留
    return CallstackResult(ok=True, candidates=cands, warnings=warns)


def render_callstack_txt(result: CallstackResult) -> str:
    lines = ["# callstack candidates (heuristic; not a full unwind)"]
    if result.error:
        lines.append(f"# error: {result.error}")
    for w in result.warnings:
        lines.append(f"# warn: {w}")
    lines.append("stack_addr\tcode_addr\tok\tfunc\tfile:line")
    for c in result.candidates:
        loc = c.get("file") or ""
        if c.get("line"):
            loc = f"{loc}:{c['line']}"
        lines.append(
            f"{c['stack_addr']}\t{c['code_addr']}\t{c['ok']}\t"
            f"{c.get('func') or ''}\t{loc}"
        )
    return "\n".join(lines) + "\n"
