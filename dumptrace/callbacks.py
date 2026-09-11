# -*- coding: utf-8 -*-
"""ASS「Callback Function List」：各任务 Entry 地址列表（可符号反查）。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


@dataclass
class CallbackEntry:
    addr: str
    func: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    ok: bool = False
    overlap: List[str] = field(default_factory=list)  # assert_pc / assert_lr / …

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CallbackTask:
    task_id: Optional[str] = None
    name: str = ""
    is_current: bool = False
    entries: List[CallbackEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "is_current": self.is_current,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class CallbacksReport:
    ok: bool
    tasks: List[CallbackTask] = field(default_factory=list)
    current: Optional[CallbackTask] = None
    overlap_count: int = 0
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "overall": self.overall,
            "current": self.current.to_dict() if self.current else None,
            "tasks": [t.to_dict() for t in self.tasks],
            "overlap_count": self.overlap_count,
            "warnings": list(self.warnings),
        }


_TASK_HDR_RE = re.compile(
    r"(?:"
    r"Current\s+thread\s+callback\s+list\s*:"
    r"|Current\s+Task\s+(-?\d+)\s+\(([^)]+)\)\s*:"
    r"|Task\s+(-?\d+|0x[0-9A-Fa-f]+)\s+\(([^)]+)\)\s*:"
    r")",
    re.I,
)
_ENTRY_RE = re.compile(r"Entry\s+at\s*\[\s*(0x[0-9A-Fa-f]+)\s*\]", re.I)


def _normalize(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "").replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    return text


def _norm_hex(addr: str) -> str:
    try:
        return f"0x{int(addr, 16) & ~1:x}"
    except ValueError:
        return addr.lower()


def parse_callbacks(
    path: Path,
    *,
    assert_addrs: Optional[Sequence[Tuple[str, str]]] = None,
) -> CallbacksReport:
    """assert_addrs: [(role, addr), ...] 用于标记与 Assert PC/LR 重叠。"""
    try:
        data = path.read_bytes()
    except OSError as e:
        return CallbacksReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _normalize(data)
    marker = re.search(r"Callback\s+Function\s+List\s*:", text, re.I)
    if not marker:
        return CallbacksReport(
            ok=False, warnings=["no Callback Function List found in .ass"]
        )

    start = marker.end()
    end_m = re.search(
        r"(?m)^\s*(?:Mutex Information:|Semaphore infomation:|Event Information:|"
        r"timer infomation:|s_handle_list|ALL created Threads)",
        text[start:],
        re.I,
    )
    end = start + end_m.start() if end_m else min(len(text), start + 200000)
    body = text[start:end]

    # 若只有菜单残留而无 Entry，则失败
    if not _ENTRY_RE.search(body):
        return CallbacksReport(
            ok=False,
            warnings=["Callback Function List header present but no Entry at [...] found"],
        )

    assert_map: Dict[str, List[str]] = {}
    for role, addr in assert_addrs or []:
        key = _norm_hex(addr)
        assert_map.setdefault(key, []).append(role)

    tasks: List[CallbackTask] = []
    current: Optional[CallbackTask] = None
    headers = list(_TASK_HDR_RE.finditer(body))
    for i, hm in enumerate(headers):
        block_end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        block = body[hm.end() : block_end]
        full = hm.group(0)
        is_current = "current" in full.lower()
        tid = hm.group(1) or hm.group(3)
        name = (hm.group(2) or hm.group(4) or "").strip()
        if is_current and not name:
            name = "CURRENT"
        task = CallbackTask(
            task_id=str(tid) if tid is not None else None,
            name=name or "UNKNOWN",
            is_current=is_current,
        )
        for em in _ENTRY_RE.finditer(block):
            addr = _norm_hex(em.group(1))
            overlap = list(assert_map.get(addr, []))
            task.entries.append(CallbackEntry(addr=addr, overlap=overlap))
        if task.entries:
            tasks.append(task)
            if is_current:
                current = task

    # 若无 Current 标题但有任务，取第一个
    if current is None and tasks:
        # 有些 dump 用 Current Task N (name)
        for t in tasks:
            if t.is_current:
                current = t
                break

    overlap_n = sum(1 for t in tasks for e in t.entries if e.overlap)
    report = CallbacksReport(
        ok=bool(tasks),
        tasks=tasks,
        current=current,
        overlap_count=overlap_n,
        overall={
            "task_count": len(tasks),
            "entry_count": sum(len(t.entries) for t in tasks),
            "current_name": current.name if current else None,
            "current_entry_count": len(current.entries) if current else 0,
            "overlap_count": overlap_n,
        },
    )
    if not report.ok:
        report.warnings.append("no callback tasks parsed")
    return report


def enrich_callbacks_symbols(
    report: CallbacksReport,
    symbols: Sequence[Any],
) -> None:
    """把 symbolize 结果填回 entries（按 addr 匹配）。"""
    by_addr: Dict[str, Any] = {}
    for s in symbols:
        addr = getattr(s, "addr", None) or (s.get("addr") if isinstance(s, dict) else None)
        if not addr:
            continue
        by_addr[_norm_hex(str(addr))] = s
    for t in report.tasks:
        for e in t.entries:
            s = by_addr.get(e.addr)
            if not s:
                continue
            ok = getattr(s, "ok", None)
            if ok is None and isinstance(s, dict):
                ok = s.get("ok")
            if not ok:
                continue
            e.ok = True
            e.func = getattr(s, "func", None) or (s.get("func") if isinstance(s, dict) else None)
            e.file = getattr(s, "file", None) or (s.get("file") if isinstance(s, dict) else None)
            e.line = getattr(s, "line", None) or (s.get("line") if isinstance(s, dict) else None)


def callback_addrs_for_symbolize(
    report: CallbacksReport, *, limit: int = 40
) -> List[Tuple[str, str]]:
    """优先当前线程 Entry，再补其它任务，去重。"""
    items: List[Tuple[str, str]] = []
    seen: Set[str] = set()

    def _add(role: str, addr: str) -> None:
        key = addr.lower()
        if key in seen:
            return
        seen.add(key)
        items.append((role, addr))

    if report.current:
        for i, e in enumerate(report.current.entries):
            _add(f"cb_current_{i}", e.addr)
            if len(items) >= limit:
                return items
    for t in report.tasks:
        if t is report.current:
            continue
        for i, e in enumerate(t.entries[:3]):
            _add(f"cb_{t.name}_{i}", e.addr)
            if len(items) >= limit:
                return items
    return items


def render_callbacks_txt(report: CallbacksReport) -> str:
    lines = [
        f"# callbacks ok={report.ok}",
        f"# overall={report.overall}",
    ]
    for w in report.warnings:
        lines.append(f"# warn: {w}")
    if report.current:
        lines += ["", f"## current ({report.current.name})"]
        for e in report.current.entries:
            ov = ",".join(e.overlap) if e.overlap else "-"
            sym = f"{e.func or ''} @ {e.file or ''}:{e.line or ''}" if e.ok else ""
            lines.append(f"- {e.addr} overlap={ov} {sym}".rstrip())
    lines += ["", "## tasks"]
    for t in report.tasks:
        cur = "*" if t.is_current else " "
        lines.append(f"{cur} {t.name} id={t.task_id} entries={len(t.entries)}")
        for e in t.entries[:12]:
            ov = ",".join(e.overlap) if e.overlap else "-"
            lines.append(f"    {e.addr} overlap={ov}")
        if len(t.entries) > 12:
            lines.append(f"    ... ({len(t.entries) - 12} more)")
    return "\n".join(lines) + "\n"
