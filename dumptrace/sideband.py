# -*- coding: utf-8 -*-
"""ASS 旁路段：Fat / NV / iram（缺段可降级 skip）。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SidebandSection:
    kind: str
    present: bool = False
    skipped: bool = False
    title: str = ""
    lines: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SidebandReport:
    ok: bool
    sections: List[SidebandSection] = field(default_factory=list)
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    skipped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "skipped": self.skipped,
            "overall": dict(self.overall),
            "sections": [s.to_dict() for s in self.sections],
            "warnings": list(self.warnings),
        }


def _normalize(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "").replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    return text


_MENU_ONLY_HINTS = re.compile(
    r"Print\s+Fat\s+system|Dump\s+Fixed\s+NV|Dump\s+Running\s+NV|"
    r"Print\s+iram\s+Information|Assert Debug Menu|Reset MCU",
    re.I,
)

# 段起始标记 → kind
_SECTION_MARKERS: List[tuple] = [
    (
        "fat",
        [
            "Fat system control block info",
            "Fat system control block information",
            "FAT system control block",
            "Fat File System Information",
        ],
    ),
    (
        "nv",
        [
            "Fixed NV",
            "Running NV",
            "NV Information",
            "NV item",
            "Dump Fixed NV",
            "Dump Running NV",
        ],
    ),
    (
        "iram",
        [
            "iram Information",
            "IRAM Information",
            "Print iram Information",
            "iram info",
        ],
    ),
]

_END_MARKERS = [
    "Mutex Information:",
    "Semaphore Information:",
    "Event Information:",
    "Callback Function List:",
    "Allocated memory info:",
    "Tasks info",
    "System Space Information",
    "Current Version:",
    "Assert Debug Menu",
    "Reset MCU",
    # 旁路段互为边界，避免互相吞并
    "Fat system control block",
    "NV Information",
    "Fixed NV",
    "Running NV",
    "iram Information",
    "IRAM Information",
]


def _slice_section(text: str, markers: List[str], *, kind: str) -> Optional[tuple]:
    start = None
    title = ""
    for mk in markers:
        # 优先行首匹配，避免菜单里的子串（如 Print iram Information）抢先命中
        for m in re.finditer(r"(?m)^\s*" + re.escape(mk) + r"\b", text, re.I):
            line_start = text.rfind("\n", 0, m.start()) + 1
            nl = text.find("\n", m.start())
            line = text[line_start : nl if nl >= 0 else len(text)]
            if re.match(r"^\s*[a-zA-Z0-9]\.\s+(Print|Dump)\b", line):
                continue
            start = m.start()
            title = mk
            break
        if start is not None:
            break
    if start is None:
        return None
    end = len(text)
    skip_self = {m.lower() for m in markers}
    for em in _END_MARKERS:
        if em.lower() in skip_self:
            continue
        if kind == "nv" and em.lower().startswith("nv"):
            continue
        if kind == "fat" and "fat system" in em.lower():
            continue
        if kind == "iram" and "iram" in em.lower():
            continue
        j = re.search(
            r"(?m)^\s*" + re.escape(em), text[start + max(len(title), 1) + 2 :], re.I
        )
        if j:
            end = min(end, start + max(len(title), 1) + 2 + j.start())
    return title, text[start:end]


def _extract_fields(body: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for ln in body.splitlines():
        s = ln.strip()
        if not s or len(s) > 200:
            continue
        if _MENU_ONLY_HINTS.search(s) and re.match(r"^[a-zA-Z0-9]\.\s+", s):
            continue
        if "=" in s:
            k, _, v = s.partition("=")
        elif ":" in s:
            k, _, v = s.partition(":")
        else:
            continue
        k, v = k.strip(), v.strip()
        if not k or not v or len(k) > 64:
            continue
        if re.match(r"^[0-9a-fA-Fx]+$", k):
            continue
        fields[k] = v
    return fields


def _useful_lines(body: str, limit: int = 80) -> List[str]:
    out: List[str] = []
    for ln in body.splitlines():
        s = ln.strip()
        if not s:
            continue
        if re.match(r"^[a-zA-Z0-9]\.\s+(Print|Dump)\b", s):
            continue
        if s.startswith("===="):
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def parse_sideband(path: Path) -> SidebandReport:
    try:
        data = path.read_bytes()
    except OSError as e:
        return SidebandReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _normalize(data)
    report = SidebandReport(ok=False)
    present_kinds: List[str] = []

    for kind, markers in _SECTION_MARKERS:
        sliced = _slice_section(text, markers, kind=kind)
        if sliced is None:
            # 菜单提及但无表体
            menu_hit = any(re.search(re.escape(m), text, re.I) for m in markers)
            sec = SidebandSection(
                kind=kind,
                present=False,
                skipped=True,
                note="menu only or absent" if menu_hit else "absent",
            )
            report.sections.append(sec)
            continue

        title, body = sliced
        lines = _useful_lines(body)
        fields = _extract_fields(body)
        # 过短且几乎只有标题 → 视为无实质内容
        meaningful = [
            ln
            for ln in lines
            if not re.search(re.escape(title), ln, re.I) or len(ln) > len(title) + 8
        ]
        if len(meaningful) < 2 and not fields:
            sec = SidebandSection(
                kind=kind,
                present=False,
                skipped=True,
                title=title,
                note="header without payload",
            )
            report.sections.append(sec)
            continue

        sec = SidebandSection(
            kind=kind,
            present=True,
            skipped=False,
            title=title,
            lines=lines[:60],
            fields=fields,
            note="ok",
        )
        report.sections.append(sec)
        present_kinds.append(kind)

    report.overall = {
        "present": present_kinds,
        "section_count": len(present_kinds),
    }
    if not present_kinds:
        report.skipped = True
        report.ok = False
        report.warnings.append(
            "Fat / NV / iram not dumped in this .ass (menu only or absent)"
        )
    else:
        report.ok = True
        report.skipped = False
    return report


def render_sideband_txt(report: SidebandReport) -> str:
    lines = [
        f"# sideband ok={report.ok} skipped={report.skipped}",
        f"overall={report.overall}",
        "",
    ]
    for sec in report.sections:
        lines.append(f"## {sec.kind} present={sec.present} skipped={sec.skipped}")
        if sec.title:
            lines.append(f"title: {sec.title}")
        if sec.note:
            lines.append(f"note: {sec.note}")
        if sec.fields:
            lines.append("fields:")
            for k, v in list(sec.fields.items())[:40]:
                lines.append(f"  {k}={v}")
        if sec.lines:
            lines.append("lines:")
            for ln in sec.lines[:40]:
                lines.append(f"  {ln}")
        lines.append("")
    if report.warnings:
        lines.append("## warnings")
        lines.extend(f"- {w}" for w in report.warnings)
    return "\n".join(lines) + "\n"
