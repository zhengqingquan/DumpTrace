# -*- coding: utf-8 -*-
"""ASS PS 任务队列 / 调用栈（缺段可降级）。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PsQueue:
    name: str
    total: Optional[int] = None
    used: Optional[int] = None
    available: Optional[int] = None
    used_pct: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PsStackFrame:
    addr: str
    index: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PsInfoReport:
    ok: bool
    queues: List[PsQueue] = field(default_factory=list)
    stack_frames: List[PsStackFrame] = field(default_factory=list)
    pressured: List[Dict[str, Any]] = field(default_factory=list)
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    skipped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "skipped": self.skipped,
            "overall": self.overall,
            "queues": [q.to_dict() for q in self.queues],
            "stack_frames": [f.to_dict() for f in self.stack_frames],
            "pressured": list(self.pressured),
            "warnings": list(self.warnings),
        }


def _normalize(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "").replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    return text


def _pct(used: int, total: int) -> Optional[float]:
    if total <= 0:
        return None
    return round(100.0 * used / total, 2)


# 常见 PS 队列表行：Name Used Total / Name Total Used Avail
_PS_QUEUE_ROW_RE = re.compile(
    r"^([A-Za-z0-9_/\- ]{2,40}?)\s+(\d+)\s+(\d+)(?:\s+(\d+))?\s*$",
    re.M,
)
_PS_ENTRY_RE = re.compile(r"Entry\s+at\s*\[\s*(0x[0-9A-Fa-f]+)\s*\]", re.I)
_MENU_NOISE_RE = re.compile(
    r"Print\s+PS|Reset MCU|Current Version|Assert Debug Menu",
    re.I,
)


def _slice_after(text: str, markers: List[str], ends: List[str]) -> Optional[str]:
    start = None
    for mk in markers:
        m = re.search(re.escape(mk), text, re.I)
        if m:
            start = m.end()
            break
    if start is None:
        return None
    end = len(text)
    for em in ends:
        j = re.search(r"(?m)^\s*" + re.escape(em), text[start + 10 :], re.I)
        if j:
            end = min(end, start + 10 + j.start())
    return text[start:end]


def parse_ps_info(path: Path, *, queue_pressure_pct: float = 80.0) -> PsInfoReport:
    try:
        data = path.read_bytes()
    except OSError as e:
        return PsInfoReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _normalize(data)
    report = PsInfoReport(ok=False)

    queue_sec = _slice_after(
        text,
        [
            "PS tasks queue information:",
            "PS tasks queue info:",
            "PS Queue Information:",
            "PS tasks queue:",
        ],
        [
            "PS function call stack",
            "Print timer",
            "Mutex Information:",
            "Callback Function List:",
            "timer infomation:",
            "Current Version:",
        ],
    )
    stack_sec = _slice_after(
        text,
        [
            "PS function call stack:",
            "PS function call stack information:",
            "PS call stack:",
        ],
        [
            "Print timer",
            "Mutex Information:",
            "Callback Function List:",
            "timer infomation:",
            "Current Version:",
            "Assert Debug Menu:",
        ],
    )

    # 菜单项后紧跟其它 Print / Version → 视为未 dump
    def _is_menu_only(sec: Optional[str]) -> bool:
        if not sec:
            return True
        head = sec[:400]
        if _MENU_NOISE_RE.search(head) and not _PS_QUEUE_ROW_RE.search(sec[:2000]):
            if not _PS_ENTRY_RE.search(sec[:2000]):
                return True
        return False

    if queue_sec and not _is_menu_only(queue_sec):
        # 去掉表头
        body = re.sub(
            r"Name\s+(?:Used\s+)?Total\s*(?:Avail(?:able)?)?\s*",
            "",
            queue_sec,
            count=1,
            flags=re.I,
        )
        for m in _PS_QUEUE_ROW_RE.finditer(body):
            name = m.group(1).strip()
            if name.lower() in ("name", "total", "used"):
                continue
            a, b, c = m.group(2), m.group(3), m.group(4)
            if c is not None:
                # Name Total Used Avail 或 Name Used Total Avail — 取较大者为 total
                nums = [int(a), int(b), int(c)]
                total = max(nums)
                avail = min(nums)
                used = total - avail
            else:
                # Name Used Total
                used, total = int(a), int(b)
                if used > total:
                    used, total = total, used
                avail = max(0, total - used)
            q = PsQueue(
                name=name,
                total=total,
                used=used,
                available=avail,
                used_pct=_pct(used, total),
            )
            report.queues.append(q)

    if stack_sec and not _is_menu_only(stack_sec):
        for i, m in enumerate(_PS_ENTRY_RE.finditer(stack_sec)):
            report.stack_frames.append(
                PsStackFrame(addr=f"0x{int(m.group(1), 16):x}", index=i)
            )

    for q in report.queues:
        if q.used_pct is not None and q.used_pct >= queue_pressure_pct:
            report.pressured.append(q.to_dict())

    if not report.queues and not report.stack_frames:
        report.skipped = True
        report.warnings.append(
            "PS tasks queue / function call stack not dumped in this .ass (menu only or absent)"
        )
        return report

    report.ok = True
    report.overall = {
        "queue_count": len(report.queues),
        "stack_frame_count": len(report.stack_frames),
        "pressured_count": len(report.pressured),
    }
    return report


def render_ps_info_txt(report: PsInfoReport) -> str:
    lines = [
        f"# ps_info ok={report.ok} skipped={report.skipped}",
        f"# overall={report.overall}",
    ]
    for w in report.warnings:
        lines.append(f"# warn: {w}")
    lines += ["", "## queues"]
    if not report.queues:
        lines.append("(none)")
    for q in report.queues:
        lines.append(
            f"- {q.name}: used={q.used}/{q.total} avail={q.available} "
            f"used_pct={q.used_pct}%"
        )
    lines += ["", "## stack_frames"]
    if not report.stack_frames:
        lines.append("(none)")
    for f in report.stack_frames[:40]:
        lines.append(f"- [{f.index}] {f.addr}")
    return "\n".join(lines) + "\n"
