# -*- coding: utf-8 -*-
"""死机前 Logel 时间线（复用 logel2txt，不重复实现 Trace 解码）。"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class TimelineEvent:
    tick_ms: int
    ue_time: str
    sn: str
    content: str
    matched_keywords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineResult:
    ok: bool
    source: str = ""
    total_lines: int = 0
    last_tick_ms: Optional[int] = None
    windows: Dict[str, List[TimelineEvent]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "source": self.source,
            "total_lines": self.total_lines,
            "last_tick_ms": self.last_tick_ms,
            "windows": {
                k: [e.to_dict() for e in v] for k, v in self.windows.items()
            },
            "warnings": self.warnings,
            "error": self.error,
        }


_HMS_RE = re.compile(r"^(\d+):(\d+):(\d+)\.(\d+)$")


def _ensure_logel2txt_path() -> Optional[Path]:
    """把同级 logel2txt 或 DUMPTRACE_LOGEL2TXT 指定路径加入 sys.path。"""
    try:
        import logel2txt  # noqa: F401

        return None
    except ImportError:
        pass
    here = Path(__file__).resolve()
    # dumptrace/timeline.py → parents[1]=仓库根，再上一级的同级 logel2txt
    candidates: List[Path] = []
    env = os.environ.get("DUMPTRACE_LOGEL2TXT")
    if env:
        candidates.append(Path(env))
    candidates.append(here.parents[1].parent / "logel2txt")
    for c in candidates:
        if (c / "logel2txt").is_dir() or (c / "logel2txt.py").is_file():
            p = str(c)
            if p not in sys.path:
                sys.path.insert(0, p)
            return c
    return None


def hms_to_ms(text: str) -> Optional[int]:
    m = _HMS_RE.match(text.strip())
    if not m:
        return None
    h, mi, s, frac = m.groups()
    ms = int(frac.ljust(3, "0")[:3])
    return ((int(h) * 60 + int(mi)) * 60 + int(s)) * 1000 + ms


def parse_trace_line(line: str) -> Optional[Tuple[str, str, str, int]]:
    """返回 (sn, ue_time, content, tick_ms)。"""
    if not line or line.startswith("SN"):
        return None
    parts = line.split("\t")
    if len(parts) < 6:
        return None
    sn = parts[0].strip()
    ue = parts[1].strip()
    content = parts[3].strip()
    tick_s = parts[5].strip()
    tick = hms_to_ms(tick_s)
    if tick is None:
        return None
    return sn, ue, content, tick


def _load_trace_lines(armlog_dir: Path) -> Tuple[List[str], str, List[str]]:
    """优先已有 txt；否则调用 logel2txt。"""
    warnings: List[str] = []
    # 已有导出
    for pat in ("*_pb.txt", "*.txt", "*.trace"):
        for p in sorted(armlog_dir.glob(pat), key=lambda x: -x.stat().st_size):
            if p.name.endswith("_log_stat.txt") or p.name.endswith("_trace.txt"):
                continue
            if p.stat().st_size < 64:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                warnings.append(f"read {p.name} failed: {e}")
                continue
            lines = text.splitlines()
            if len(lines) > 2 and "\t" in lines[1]:
                return lines, f"file:{p}", warnings

    _ensure_logel2txt_path()
    try:
        from logel2txt.discover import resolve_inputs
        from logel2txt.exporters import export_from_logel_raw, export_from_traceview
    except ImportError as e:
        raise ImportError(
            "logel2txt not found; clone https://github.com/zhengqingquan/logel2txt "
            "and set PYTHONPATH / DUMPTRACE_LOGEL2TXT (or place as sibling repo)"
        ) from e

    mode, payload = resolve_inputs(armlog_dir)
    if mode == "traceview":
        dat, pbs = payload  # type: ignore
        lines = export_from_traceview(dat, pbs, 0)
        src = f"traceview:{dat.parent.name}"
        if "_pb" not in dat.parent.name.lower():
            warnings.append("traceview not under *_pb; timeline may be incomplete")
        return lines, src, warnings
    if mode == "logel":
        logel = payload  # type: ignore
        lines = export_from_logel_raw(logel, 0)
        warnings.append("plaintext logel extract (incomplete vs Export Trace)")
        return lines, f"logel:{logel.name}", warnings
    raise FileNotFoundError(f"unsupported logel2txt mode: {mode}")


def build_timeline(
    armlog_dir: Path,
    *,
    keywords: Sequence[str],
    windows_sec: Sequence[int] = (3, 10, 60),
    max_events_per_window: int = 80,
) -> TimelineResult:
    try:
        lines, source, warns = _load_trace_lines(armlog_dir)
    except Exception as e:
        return TimelineResult(
            ok=False,
            error=f"{type(e).__name__}: {e}",
            warnings=[str(e)],
        )

    events: List[Tuple[str, str, str, int]] = []
    for line in lines:
        parsed = parse_trace_line(line)
        if parsed:
            events.append(parsed)

    if not events:
        return TimelineResult(
            ok=False,
            source=source,
            total_lines=max(0, len(lines) - 1),
            error="no parseable trace rows",
            warnings=warns,
        )

    last_tick = max(e[3] for e in events)
    kws = [k.lower() for k in keywords if k]
    result = TimelineResult(
        ok=True,
        source=source,
        total_lines=len(events),
        last_tick_ms=last_tick,
        warnings=warns,
    )

    for sec in windows_sec:
        start = max(0, last_tick - int(sec) * 1000)
        key = f"{sec}s"
        matched: List[TimelineEvent] = []
        for sn, ue, content, tick in events:
            if tick < start or tick > last_tick:
                continue
            cl = content.lower()
            hits = [k for k in kws if k in cl]
            if kws and not hits:
                continue
            matched.append(
                TimelineEvent(
                    tick_ms=tick,
                    ue_time=ue,
                    sn=sn,
                    content=content[:300],
                    matched_keywords=hits,
                )
            )
        # 取末尾 max 条（更靠近死机）
        if len(matched) > max_events_per_window:
            matched = matched[-max_events_per_window:]
        result.windows[key] = matched

    return result


def render_timeline_txt(tl: TimelineResult) -> str:
    lines = [
        f"# timeline ok={tl.ok} source={tl.source} lines={tl.total_lines} "
        f"last_tick_ms={tl.last_tick_ms}",
    ]
    if tl.error:
        lines.append(f"# error: {tl.error}")
    for w in tl.warnings:
        lines.append(f"# warn: {w}")
    for win, evs in tl.windows.items():
        lines.append(f"\n## window={win} events={len(evs)}")
        for e in evs:
            k = ",".join(e.matched_keywords) if e.matched_keywords else "-"
            lines.append(
                f"{e.ue_time}\t{e.sn}\ttick_ms={e.tick_ms}\tkw={k}\t{e.content}"
            )
    return "\n".join(lines) + "\n"
