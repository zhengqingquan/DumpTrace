# -*- coding: utf-8 -*-
"""符号文件匹配：文件名片段 / 编译时间 / Build ID / map 校验。"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MatchCheck:
    """单项匹配结果。"""

    name: str
    status: str  # match | mismatch | skip
    message: str
    ass_value: Optional[str] = None
    other_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SymbolMatchReport:
    checks: List[MatchCheck] = field(default_factory=list)
    overall: Optional[bool] = None  # True 全通过；False 有 mismatch；None 无可用检查

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": self.overall,
            "checks": [c.to_dict() for c in self.checks],
        }

    @property
    def warnings(self) -> List[str]:
        out: List[str] = []
        for c in self.checks:
            if c.status == "mismatch":
                out.append(f"symbol_check[{c.name}] mismatch: {c.message}")
            elif c.status == "skip" and c.name != "map_checksum":
                # map 缺失常见，由 CLI INFO 提示；其余 skip 进警告便于察觉
                out.append(f"symbol_check[{c.name}] skip: {c.message}")
        return out


_DATE_RE = re.compile(rb"(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})")
_PROJECT_RE = re.compile(
    rb"Project Version:\s*([A-Za-z0-9_.\-]+)", re.IGNORECASE
)
_ENTRY_RE = re.compile(
    r"Image Entry point\s*:\s*(0x[0-9A-Fa-f]+)", re.IGNORECASE
)
_RO_RE = re.compile(
    r"Total RO\s+Size\s*\([^)]*\)\s+(\d+)", re.IGNORECASE
)
_ROM_RE = re.compile(
    r"Total ROM Size\s*\([^)]*\)\s+(\d+)", re.IGNORECASE
)
_ARMLINK_RE = re.compile(r"armlink\s*\[([0-9A-Fa-f]+)\]", re.IGNORECASE)
_BUILD_ID_RE = re.compile(r"(CD\d+|EX\d+)", re.I)
_BUILD_ID_FALLBACK_RE = re.compile(r"(COM_[A-Z0-9]+|V\d+_\d+)", re.I)


def version_token(project_version: str) -> str:
    """从 Project Version 抽可用于文件名比对的片段，优先 CD/EX 构建号。"""
    m = _BUILD_ID_RE.search(project_version)
    if m:
        return m.group(1)
    m = _BUILD_ID_FALLBACK_RE.search(project_version)
    if m:
        return m.group(1)
    parts = re.split(r"[\\/\s]+", project_version.strip())
    return parts[-1] if parts else project_version


def find_sibling_map(axf: Path, search_roots: Optional[List[Path]] = None) -> Optional[Path]:
    """优先同 stem 的 .map，其次在搜索根下找同名。"""
    direct = axf.with_suffix(".map")
    if direct.is_file():
        return direct.resolve()
    roots = list(search_roots or [])
    roots.extend([axf.parent, axf.parent.parent])
    seen = set()
    for root in roots:
        if root is None or not root.is_dir():
            continue
        key = str(root.resolve())
        if key in seen:
            continue
        seen.add(key)
        cand = root / f"{axf.stem}.map"
        if cand.is_file():
            return cand.resolve()
    return None


def extract_axf_meta(axf: Path) -> Dict[str, Optional[str]]:
    """从 .axf 可打印串提取固件版本元数据与 ELF 入口。"""
    data = axf.read_bytes()
    meta: Dict[str, Optional[str]] = {
        "project_version": None,
        "build_time": None,
        "build_id": None,
        "elf_entry": None,
    }
    m = _PROJECT_RE.search(data)
    if m:
        # 过滤纯格式串占位（如仅 %s）
        pv = m.group(1).decode("ascii", errors="ignore").strip()
        if pv and "%" not in pv and len(pv) >= 4:
            meta["project_version"] = pv
            meta["build_id"] = version_token(pv)
    # 若首个 Project Version 是格式串，再扫后续
    if meta["project_version"] is None:
        for m in _PROJECT_RE.finditer(data):
            pv = m.group(1).decode("ascii", errors="ignore").strip()
            if pv and "%" not in pv and len(pv) >= 4:
                meta["project_version"] = pv
                meta["build_id"] = version_token(pv)
                break
    dm = _DATE_RE.search(data)
    if dm:
        meta["build_time"] = dm.group(1).decode("ascii")
    meta["elf_entry"] = _elf_entry_hex(data)
    return meta


def _elf_entry_hex(data: bytes) -> Optional[str]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == 1 else ">"
    try:
        if ei_class == 1:
            entry = struct.unpack_from(endian + "I", data, 24)[0]
        elif ei_class == 2 and len(data) >= 32:
            entry = struct.unpack_from(endian + "Q", data, 24)[0]
        else:
            return None
    except struct.error:
        return None
    return f"0x{entry:x}"


def extract_map_fingerprint(map_path: Path) -> Dict[str, Optional[str]]:
    """从 armlink .map 抽取入口/体积/工具号，并生成短校验摘要。"""
    # Entry / Totals 多在文件后部，但距尾可能超过数百 KB；整文件一次读入可接受
    text = map_path.read_text(encoding="utf-8", errors="ignore")
    entry = None
    m = _ENTRY_RE.search(text)
    if m:
        entry = m.group(1).lower()
    ro = _RO_RE.search(text)
    rom = _ROM_RE.search(text)
    link = _ARMLINK_RE.search(text)
    parts = {
        "entry": entry,
        "total_ro": ro.group(1) if ro else None,
        "total_rom": rom.group(1) if rom else None,
        "armlink_id": link.group(1).lower() if link else None,
    }
    fp = ";".join(f"{k}={v}" for k, v in parts.items() if v) or f"size={map_path.stat().st_size}"
    parts["digest"] = hashlib.sha256(fp.encode("utf-8")).hexdigest()[:16]
    parts["fingerprint"] = fp
    return parts


def assess_symbol_match(
    *,
    axf: Optional[Path],
    map_path: Optional[Path] = None,
    project_version: Optional[str] = None,
    build_time: Optional[str] = None,
) -> SymbolMatchReport:
    """对 name_token / build_time / build_id / map_checksum 分别判定。"""
    report = SymbolMatchReport()
    if axf is None or not axf.is_file():
        report.checks.append(
            MatchCheck(
                name="name_token",
                status="skip",
                message="no .axf; symbol match skipped",
            )
        )
        report.checks.append(
            MatchCheck(
                name="build_time",
                status="skip",
                message="no .axf",
                ass_value=build_time,
            )
        )
        report.checks.append(
            MatchCheck(
                name="build_id",
                status="skip",
                message="no .axf",
                ass_value=project_version,
            )
        )
        report.checks.append(
            MatchCheck(
                name="map_checksum",
                status="skip",
                message="no .axf",
            )
        )
        report.overall = None
        return report

    try:
        axf_meta = extract_axf_meta(axf)
    except OSError as e:
        for name in ("name_token", "build_time", "build_id", "map_checksum"):
            report.checks.append(
                MatchCheck(name=name, status="skip", message=f"read axf failed: {e}")
            )
        report.overall = None
        return report

    # 1) 文件名片段
    token = version_token(project_version) if project_version else ""
    if not token:
        report.checks.append(
            MatchCheck(
                name="name_token",
                status="skip",
                message="ASS Project Version missing; cannot check axf filename",
                other_value=axf.name,
            )
        )
    elif token.lower() in axf.name.lower():
        report.checks.append(
            MatchCheck(
                name="name_token",
                status="match",
                message=f"token '{token}' found in {axf.name}",
                ass_value=token,
                other_value=axf.name,
            )
        )
    else:
        report.checks.append(
            MatchCheck(
                name="name_token",
                status="mismatch",
                message=f"token '{token}' not in axf name {axf.name}",
                ass_value=token,
                other_value=axf.name,
            )
        )

    # 2) 编译时间
    axf_time = axf_meta.get("build_time")
    if not build_time:
        report.checks.append(
            MatchCheck(
                name="build_time",
                status="skip",
                message="ASS build_time missing",
                other_value=axf_time,
            )
        )
    elif not axf_time:
        report.checks.append(
            MatchCheck(
                name="build_time",
                status="skip",
                message="axf has no embedded build time string",
                ass_value=build_time,
            )
        )
    elif _norm_time(build_time) == _norm_time(axf_time):
        report.checks.append(
            MatchCheck(
                name="build_time",
                status="match",
                message=f"ass={build_time} axf={axf_time}",
                ass_value=build_time,
                other_value=axf_time,
            )
        )
    else:
        report.checks.append(
            MatchCheck(
                name="build_time",
                status="mismatch",
                message=f"ass={build_time} axf={axf_time}",
                ass_value=build_time,
                other_value=axf_time,
            )
        )

    # 3) Build ID（以 Project Version / CD|EX 号为准）
    ass_id = version_token(project_version) if project_version else None
    axf_id = axf_meta.get("build_id")
    axf_pv = axf_meta.get("project_version")
    if not project_version:
        report.checks.append(
            MatchCheck(
                name="build_id",
                status="skip",
                message="ASS Project Version missing",
                other_value=axf_pv,
            )
        )
    elif not axf_pv:
        report.checks.append(
            MatchCheck(
                name="build_id",
                status="skip",
                message="axf has no embedded Project Version",
                ass_value=project_version,
            )
        )
    else:
        full_ok = _norm_ver(project_version) == _norm_ver(axf_pv)
        id_ok = bool(ass_id and axf_id and ass_id.lower() == axf_id.lower())
        if full_ok or id_ok:
            report.checks.append(
                MatchCheck(
                    name="build_id",
                    status="match",
                    message=f"ass={project_version} axf={axf_pv}",
                    ass_value=project_version,
                    other_value=axf_pv,
                )
            )
        else:
            report.checks.append(
                MatchCheck(
                    name="build_id",
                    status="mismatch",
                    message=f"ass={project_version} axf={axf_pv}",
                    ass_value=project_version,
                    other_value=axf_pv,
                )
            )

    # 4) map 校验：同 stem + ELF 入口 vs map Image Entry + 摘要指纹
    if map_path is None:
        map_path = find_sibling_map(axf)
    if map_path is None or not map_path.is_file():
        report.checks.append(
            MatchCheck(
                name="map_checksum",
                status="skip",
                message=f"no sibling .map for {axf.name}",
                other_value=axf_meta.get("elf_entry"),
            )
        )
    else:
        try:
            mp = extract_map_fingerprint(map_path)
        except OSError as e:
            report.checks.append(
                MatchCheck(
                    name="map_checksum",
                    status="skip",
                    message=f"read map failed: {e}",
                )
            )
            mp = None
        if mp is not None:
            stem_ok = map_path.stem.lower() == axf.stem.lower()
            elf_entry = (axf_meta.get("elf_entry") or "").lower()
            map_entry = (mp.get("entry") or "").lower()
            entry_ok = bool(elf_entry and map_entry and elf_entry == map_entry)
            digest = mp.get("digest") or "?"
            detail = (
                f"map={map_path.name} stem={'ok' if stem_ok else 'diff'} "
                f"entry axf={elf_entry or 'n/a'} map={map_entry or 'n/a'} "
                f"digest={digest}"
            )
            if stem_ok and entry_ok:
                report.checks.append(
                    MatchCheck(
                        name="map_checksum",
                        status="match",
                        message=detail,
                        ass_value=elf_entry,
                        other_value=f"{map_entry};{digest}",
                    )
                )
            elif not stem_ok or (elf_entry and map_entry and not entry_ok):
                report.checks.append(
                    MatchCheck(
                        name="map_checksum",
                        status="mismatch",
                        message=detail,
                        ass_value=elf_entry,
                        other_value=f"{map_entry};{digest}",
                    )
                )
            else:
                report.checks.append(
                    MatchCheck(
                        name="map_checksum",
                        status="skip",
                        message=detail + " (insufficient entry fields)",
                        ass_value=elf_entry,
                        other_value=f"{map_entry};{digest}",
                    )
                )

    statuses = [c.status for c in report.checks]
    if any(s == "mismatch" for s in statuses):
        report.overall = False
    elif any(s == "match" for s in statuses):
        report.overall = True
    else:
        report.overall = None
    return report


def _norm_time(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _norm_ver(value: str) -> str:
    return re.sub(r"\s+", "", value.strip()).lower()
