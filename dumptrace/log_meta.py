# -*- coding: utf-8 -*-
"""旁路抓取元数据：.lst / Dump LogSave / 现场文件完整性。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


_LOGSAVE_HEADER_RE = re.compile(
    r"Dump\s+LogSave\s+(ArmLog|DspLog|IQ)\s+Memory",
    re.I,
)
_NO_LOGSAVE_RE = re.compile(
    r"no\s+logsave\s+(armlog|dsplog|iq)\b",
    re.I,
)
_MEM_DUMP_RE = re.compile(
    r"Memory\s+Dumping\s+Finished\s*:\s*begin\s+addr\s*=\s*(0x[0-9A-Fa-f]+)\s*,\s*"
    r"total\s+size\s*=\s*(\d+)\s*Byte\s*\((0x[0-9A-Fa-f]+)\)",
    re.I,
)


@dataclass
class LogSaveChannel:
    name: str
    present: bool = False
    empty: bool = True
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileIntegrity:
    role: str
    path: str = ""
    size: int = 0
    present: bool = False
    empty: bool = True
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LstMeta:
    path: str = ""
    size: int = 0
    lines: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LogMetaReport:
    ok: bool
    logsave: List[LogSaveChannel] = field(default_factory=list)
    mem_dump: Dict[str, Any] = field(default_factory=dict)
    files: List[FileIntegrity] = field(default_factory=list)
    lst: Optional[LstMeta] = None
    integrity: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "logsave": [c.to_dict() for c in self.logsave],
            "mem_dump": dict(self.mem_dump),
            "files": [f.to_dict() for f in self.files],
            "lst": self.lst.to_dict() if self.lst else None,
            "integrity": dict(self.integrity),
            "warnings": list(self.warnings),
        }


def _normalize(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "").replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    return text


def _parse_logsave(text: str) -> List[LogSaveChannel]:
    channels: Dict[str, LogSaveChannel] = {}
    for m in _LOGSAVE_HEADER_RE.finditer(text):
        name = m.group(1)
        key = name.lower()
        # 取 header 后一小段判断是否 empty
        chunk = text[m.end() : m.end() + 240]
        empty = bool(_NO_LOGSAVE_RE.search(chunk)) or (
            "no logsave" in chunk.lower()
        )
        detail = ""
        nm = _NO_LOGSAVE_RE.search(chunk)
        if nm:
            detail = nm.group(0).strip()
        elif empty:
            detail = "no payload after header"
        else:
            detail = "payload present (or unrecognized)"
            empty = False
        channels[key] = LogSaveChannel(
            name=name, present=True, empty=empty, detail=detail
        )
    # 保证三通道键齐全（便于报告）
    for name in ("ArmLog", "DspLog", "IQ"):
        key = name.lower()
        if key not in channels:
            channels[key] = LogSaveChannel(
                name=name, present=False, empty=True, detail="section not found"
            )
    order = ["armlog", "dsplog", "iq"]
    return [channels[k] for k in order]


def _parse_mem_dump_note(text: str) -> Dict[str, Any]:
    m = _MEM_DUMP_RE.search(text)
    if not m:
        return {}
    return {
        "begin_addr": m.group(1).lower(),
        "total_size": int(m.group(2)),
        "total_size_hex": m.group(3).lower(),
    }


def _parse_lst(path: Path) -> LstMeta:
    meta = LstMeta(path=str(path), size=path.stat().st_size)
    try:
        raw = path.read_bytes()
    except OSError:
        return meta
    text = raw.decode("utf-8", errors="ignore") or raw.decode("latin-1", errors="ignore")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    meta.lines = lines[:40]
    fields: Dict[str, str] = {}
    for ln in lines[:80]:
        if "=" in ln:
            k, _, v = ln.partition("=")
            k, v = k.strip(), v.strip()
            if k and v and len(k) < 80:
                fields[k] = v
        elif ":" in ln:
            k, _, v = ln.partition(":")
            k, v = k.strip(), v.strip()
            if k and v and len(k) < 80 and not k.startswith("http"):
                fields[k] = v
    meta.fields = fields
    return meta


def _file_integrity(
    role: str,
    path: Optional[Path],
    *,
    note: str = "",
) -> FileIntegrity:
    if path is None or not path.exists():
        return FileIntegrity(role=role, present=False, empty=True, note=note or "missing")
    try:
        size = path.stat().st_size if path.is_file() else 0
    except OSError as e:
        return FileIntegrity(
            role=role, path=str(path), present=True, empty=True, note=str(e)
        )
    empty = size <= 0
    return FileIntegrity(
        role=role,
        path=str(path),
        size=size,
        present=True,
        empty=empty,
        note=note or ("empty" if empty else "ok"),
    )


def parse_log_meta(
    *,
    ass_path: Optional[Path] = None,
    armlog_dir: Optional[Path] = None,
    package_files: Optional[Sequence[Any]] = None,
    lst_path: Optional[Path] = None,
) -> LogMetaReport:
    """解析 LogSave / .lst，并汇总现场文件完整性。"""
    report = LogMetaReport(ok=False)
    text = ""
    if ass_path is not None and ass_path.is_file():
        try:
            text = _normalize(ass_path.read_bytes())
        except OSError as e:
            report.warnings.append(f"read ass failed: {e}")

    if text:
        report.logsave = _parse_logsave(text)
        report.mem_dump = _parse_mem_dump_note(text)

    # 文件清单：优先用 package_files；否则扫描 armlog
    roles_seen = set()
    if package_files:
        for ent in package_files:
            role = getattr(ent, "role", None) or (ent.get("role") if isinstance(ent, dict) else None)
            path_v = getattr(ent, "path", None) or (ent.get("path") if isinstance(ent, dict) else None)
            if not role:
                continue
            roles_seen.add(str(role))
            p = Path(path_v) if path_v else None
            report.files.append(_file_integrity(str(role), p))
    if armlog_dir is not None and armlog_dir.is_dir():
        extras = {
            "iq": _pick_first(armlog_dir, ["*.iq", "*_iq*"]),
        }
        for role, p in extras.items():
            if role in roles_seen:
                continue
            if p is not None:
                report.files.append(_file_integrity(role, p))

    lst = lst_path
    if lst is None and package_files:
        for ent in package_files:
            role = getattr(ent, "role", None) or (ent.get("role") if isinstance(ent, dict) else None)
            if role == "lst":
                path_v = getattr(ent, "path", None) or (ent.get("path") if isinstance(ent, dict) else None)
                if path_v:
                    lst = Path(path_v)
                break
    if lst is None and armlog_dir is not None:
        lst = _pick_first(armlog_dir, ["*.lst"])
    if lst is not None and lst.is_file():
        report.lst = _parse_lst(lst)
    else:
        report.warnings.append(".lst not found")

    empty_logsave = [c.name for c in report.logsave if c.present and c.empty]
    missing_logsave = [c.name for c in report.logsave if not c.present]
    critical = {f.role: f for f in report.files}
    gaps: List[str] = []
    for role in ("ass", "mem", "logel"):
        f = critical.get(role)
        if f is None or not f.present:
            gaps.append(f"{role}:missing")
        elif f.empty:
            gaps.append(f"{role}:empty")

    # mem size vs ASS dump note
    mem_mismatch = None
    mem_f = critical.get("mem")
    if mem_f and mem_f.present and report.mem_dump.get("total_size"):
        expected = int(report.mem_dump["total_size"])
        if mem_f.size and abs(mem_f.size - expected) > 64:
            mem_mismatch = {
                "file_size": mem_f.size,
                "ass_total_size": expected,
            }
            gaps.append("mem:size_mismatch")

    report.integrity = {
        "logsave_empty": empty_logsave,
        "logsave_missing_sections": missing_logsave,
        "gaps": gaps,
        "complete": len(gaps) == 0,
        "mem_size_mismatch": mem_mismatch,
        "has_lst": report.lst is not None,
    }
    report.ok = True
    if gaps:
        report.warnings.append("capture gaps: " + ", ".join(gaps))
    if empty_logsave and len(empty_logsave) == sum(1 for c in report.logsave if c.present):
        report.warnings.append(
            "all Dump LogSave channels empty (no logsave ArmLog/DspLog/IQ)"
        )
    return report


def _pick_first(directory: Path, patterns: Sequence[str]) -> Optional[Path]:
    found: List[Path] = []
    for pat in patterns:
        found.extend(p for p in directory.glob(pat) if p.is_file())
    if not found:
        return None
    return max(found, key=lambda p: p.stat().st_size)


def render_log_meta_txt(report: LogMetaReport) -> str:
    lines = [
        f"# log_meta ok={report.ok}",
        "",
        "## integrity",
    ]
    integ = report.integrity or {}
    lines.append(f"complete={integ.get('complete')} gaps={integ.get('gaps')}")
    lines.append(f"logsave_empty={integ.get('logsave_empty')}")
    if integ.get("mem_size_mismatch"):
        lines.append(f"mem_size_mismatch={integ.get('mem_size_mismatch')}")
    lines += ["", "## LogSave"]
    if not report.logsave:
        lines.append("(none)")
    for c in report.logsave:
        lines.append(
            f"- {c.name}: present={c.present} empty={c.empty} detail={c.detail}"
        )
    if report.mem_dump:
        lines += ["", "## ASS mem dump note", str(report.mem_dump)]
    lines += ["", "## files"]
    for f in report.files:
        lines.append(
            f"- {f.role}: present={f.present} empty={f.empty} "
            f"size={f.size} note={f.note}"
        )
    lines += ["", "## lst"]
    if report.lst:
        lines.append(f"path={report.lst.path} size={report.lst.size}")
        if report.lst.fields:
            lines.append("fields:")
            for k, v in list(report.lst.fields.items())[:30]:
                lines.append(f"  {k}={v}")
        if report.lst.lines:
            lines.append("head:")
            for ln in report.lst.lines[:20]:
                lines.append(f"  {ln}")
    else:
        lines.append("(none)")
    if report.warnings:
        lines += ["", "## warnings"]
        lines.extend(f"- {w}" for w in report.warnings)
    return "\n".join(lines) + "\n"
