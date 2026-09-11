# -*- coding: utf-8 -*-
"""dumptrace.toml 配置加载（标准库子集解析，无第三方依赖）。"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


from dumptrace.rtos_info import DEFAULT_TIMER_MODULES


@dataclass
class DumpTraceConfig:
    addr2line: Optional[Path] = None
    copy_ass: bool = False
    bundle: bool = False
    full: bool = False
    strict_symbols: bool = False
    warn_lost_pct: float = 5.0
    bad_lost_pct: float = 15.0
    timeline_keywords: List[str] = field(
        default_factory=lambda: [
            "camera",
            "preview",
            "encode",
            "stream",
            "assert",
            "abort",
            "exception",
            "T_P_APP",
            "IMG_",
            "display",
        ]
    )
    timeline_windows_sec: List[int] = field(default_factory=lambda: [3, 10, 60])
    enable_timeline: bool = True
    enable_mem: bool = True
    mem_base: str = "0x80000000"
    code_ranges: List[str] = field(
        default_factory=lambda: ["0x60000000-0x62000000"]
    )
    queue_pressure_pct: float = 80.0
    stack_overflow_pct: float = 90.0
    timer_modules: Dict[str, List[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_TIMER_MODULES.items()}
    )
    source_path: Optional[Path] = None

    def merged_with_cli(
        self,
        *,
        addr2line: Optional[Path] = None,
        copy_ass: bool = False,
        bundle: bool = False,
        full: bool = False,
        strict_symbols: bool = False,
        skip_timeline: bool = False,
        skip_mem: bool = False,
    ) -> "DumpTraceConfig":
        return replace(
            self,
            addr2line=addr2line or self.addr2line,
            copy_ass=copy_ass or self.copy_ass,
            bundle=bundle or self.bundle,
            full=full or self.full,
            strict_symbols=strict_symbols or self.strict_symbols,
            enable_timeline=False if skip_timeline else self.enable_timeline,
            enable_mem=False if skip_mem else self.enable_mem,
        )


def _parse_scalar(raw: str) -> Any:
    s = raw.strip()
    if s.startswith("#"):
        return None
    if "#" in s:
        in_str = False
        out = []
        for ch in s:
            if ch == '"':
                in_str = not in_str
            if ch == "#" and not in_str:
                break
            out.append(ch)
        s = "".join(out).strip()
    if s.lower() in ("true", "false"):
        return s.lower() == "true"
    if (s.startswith('"') and s.endswith('"')) or (
        s.startswith("'") and s.endswith("'")
    ):
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        items = []
        for part in inner.split(","):
            part = part.strip()
            if not part:
                continue
            items.append(_parse_scalar(part))
        return items
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


def parse_simple_toml(text: str) -> Dict[str, Any]:
    root: Dict[str, Any] = {}
    section: Optional[str] = None
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw.startswith("[") and raw.endswith("]"):
            section = raw[1:-1].strip()
            root.setdefault(section, {})
            continue
        if "=" not in raw:
            continue
        key, _, val = raw.partition("=")
        key = key.strip()
        value = _parse_scalar(val)
        if value is None:
            continue
        if section is None:
            root[key] = value
        else:
            root.setdefault(section, {})[key] = value
    return root


def config_from_dict(data: Dict[str, Any], source: Optional[Path] = None) -> DumpTraceConfig:
    tools = data.get("tools") or {}
    export = data.get("export") or {}
    cred = data.get("credibility") or {}
    timeline = data.get("timeline") or {}
    mem = data.get("mem") or {}
    rtos = data.get("rtos") or {}
    timer_mods = data.get("timer_modules") or {}

    addr = tools.get("addr2line") or data.get("addr2line")
    kw = timeline.get("keywords")
    wins = timeline.get("windows_sec")
    ranges = mem.get("code_ranges")
    cfg = DumpTraceConfig(
        addr2line=Path(addr) if addr else None,
        copy_ass=bool(export.get("copy_ass", False)),
        bundle=bool(export.get("bundle", False)),
        full=bool(export.get("full", False)),
        strict_symbols=bool(export.get("strict_symbols", False)),
        warn_lost_pct=float(cred.get("warn_lost_pct", 5.0)),
        bad_lost_pct=float(cred.get("bad_lost_pct", 15.0)),
        enable_timeline=bool(timeline.get("enable", True)),
        enable_mem=bool(mem.get("enable", True)),
        mem_base=str(mem.get("base", "0x80000000")),
        queue_pressure_pct=float(rtos.get("queue_pressure_pct", 80.0)),
        stack_overflow_pct=float(rtos.get("stack_overflow_pct", 90.0)),
        source_path=source,
    )
    if isinstance(kw, list) and kw:
        cfg.timeline_keywords = [str(x) for x in kw]
    if isinstance(wins, list) and wins:
        cfg.timeline_windows_sec = [int(x) for x in wins]
    if isinstance(ranges, list) and ranges:
        cfg.code_ranges = [str(x) for x in ranges]
    if isinstance(timer_mods, dict) and timer_mods:
        merged = {k: list(v) for k, v in DEFAULT_TIMER_MODULES.items()}
        for k, v in timer_mods.items():
            if isinstance(v, list) and v:
                merged[str(k)] = [str(x) for x in v]
        cfg.timer_modules = merged
    return cfg


def load_config(path: Optional[Union[str, Path]] = None) -> DumpTraceConfig:
    candidates: List[Path] = []
    if path is not None:
        candidates.append(Path(path).expanduser())
    candidates.append(Path.cwd() / "dumptrace.toml")

    for p in candidates:
        if p.is_file():
            text = p.read_text(encoding="utf-8")
            data = parse_simple_toml(text)
            return config_from_dict(data, source=p.resolve())
    return DumpTraceConfig()


def find_config_near(input_path: Path) -> Optional[Path]:
    cur = input_path if input_path.is_dir() else input_path.parent
    for _ in range(6):
        cand = cur / "dumptrace.toml"
        if cand.is_file():
            return cand
        if cur.parent == cur:
            break
        cur = cur.parent
    return None
