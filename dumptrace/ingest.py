# -*- coding: utf-8 -*-
"""死机包接入与校验。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class FileEntry:
    role: str
    path: Path
    size: int
    usable: bool
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["path"] = str(self.path)
        return d


@dataclass
class PackageInfo:
    root: Path
    armlog_dir: Path
    dump_id: str
    files: List[FileEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    axf_match: Optional[bool] = None
    symbol_match: Optional[Dict[str, Any]] = None

    @property
    def ass_path(self) -> Optional[Path]:
        for f in self.files:
            if f.role == "ass" and f.usable:
                return f.path
        return None

    @property
    def axf_path(self) -> Optional[Path]:
        for f in self.files:
            if f.role == "axf" and f.usable:
                return f.path
        return None

    @property
    def map_path(self) -> Optional[Path]:
        for f in self.files:
            if f.role == "map" and f.usable:
                return f.path
        return None

    def get(self, role: str) -> Optional[FileEntry]:
        for f in self.files:
            if f.role == role:
                return f
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": str(self.root),
            "armlog_dir": str(self.armlog_dir),
            "dump_id": self.dump_id,
            "files": [f.to_dict() for f in self.files],
            "warnings": list(self.warnings),
            "axf_match": self.axf_match,
            "symbol_match": self.symbol_match,
        }


def _entry(role: str, path: Optional[Path], *, usable: Optional[bool] = None, note: str = "") -> Optional[FileEntry]:
    if path is None or not path.exists():
        return None
    size = path.stat().st_size if path.is_file() else 0
    if usable is None:
        usable = path.is_file() and size > 0
    return FileEntry(role=role, path=path.resolve(), size=size, usable=bool(usable), note=note)


def _pick_ass(armlog: Path) -> Optional[Path]:
    """优先非 _pb 的 .ass。"""
    ass_files = [p for p in armlog.glob("*.ass") if p.is_file()]
    if not ass_files:
        return None
    primary = [p for p in ass_files if not p.stem.endswith("_pb")]
    pool = primary or ass_files
    return max(pool, key=lambda p: p.stat().st_size)


def _pick_by_suffix(armlog: Path, suffix: str, prefer_non_pb: bool = True) -> Optional[Path]:
    files = [p for p in armlog.glob(f"*{suffix}") if p.is_file()]
    if not files:
        return None
    if prefer_non_pb:
        primary = [p for p in files if "_pb" not in p.name]
        files = primary or files
    return max(files, key=lambda p: p.stat().st_size)


def _find_armlog_dirs(root: Path) -> List[Path]:
    if root.is_dir() and root.name.endswith("_armlog"):
        return [root]
    found = [p for p in root.rglob("*_armlog") if p.is_dir()]
    # 也接受本身就是 armlog 内容（含 .ass）的目录
    if not found and list(root.glob("*.ass")):
        return [root]
    return sorted(found)


def _find_axf(search_roots: List[Path], explicit: Optional[Path] = None) -> Optional[Path]:
    if explicit is not None:
        p = explicit.expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"axf not found: {p}")
        return p
    candidates: List[Path] = []
    for root in search_roots:
        if root.is_file():
            continue
        candidates.extend(root.glob("*.axf"))
        if root.parent.is_dir():
            candidates.extend(root.parent.glob("*.axf"))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def _dump_id_from(armlog: Path, ass: Optional[Path]) -> str:
    if ass is not None:
        stem = ass.stem
        if stem.endswith("_pb"):
            stem = stem[: -len("_pb")]
        return stem
    name = armlog.name
    if name.endswith("_armlog"):
        return name[: -len("_armlog")]
    return name


def ingest(
    input_path: Path,
    *,
    axf: Optional[Path] = None,
    project_version: Optional[str] = None,
) -> PackageInfo:
    """
    识别 dump / armlog 布局。
    缺 ASS 抛 FileNotFoundError；缺 AXF 仅警告并降级。
    """
    input_path = input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"input path not found: {input_path}")

    if input_path.is_file() and input_path.suffix.lower() == ".ass":
        armlog_dir = input_path.parent
        root = armlog_dir.parent if armlog_dir.name.endswith("_armlog") else armlog_dir
        armlog_dirs = [armlog_dir]
    else:
        root = input_path if input_path.is_dir() else input_path.parent
        armlog_dirs = _find_armlog_dirs(root)
        if not armlog_dirs:
            raise FileNotFoundError(
                f"no *_armlog directory or .ass found under: {input_path}"
            )

    armlog_dir = armlog_dirs[0]
    ass = _pick_ass(armlog_dir)
    if ass is None:
        raise FileNotFoundError(f"no .ass found under: {armlog_dir}")

    dump_id = _dump_id_from(armlog_dir, ass)
    info = PackageInfo(root=root, armlog_dir=armlog_dir, dump_id=dump_id)

    def add(entry: Optional[FileEntry]) -> None:
        if entry is not None:
            info.files.append(entry)

    add(_entry("ass", ass, usable=True))
    add(_entry("logel", _pick_by_suffix(armlog_dir, ".logel")))
    add(_entry("mem", _pick_by_suffix(armlog_dir, "_1.mem") or _pick_by_suffix(armlog_dir, ".mem")))
    add(_entry("log_stat", _pick_by_suffix(armlog_dir, "_log_stat.txt")))
    add(_entry("lst", _pick_by_suffix(armlog_dir, ".lst"), usable=True, note="may be small"))
    add(_entry("iq", _pick_by_suffix(armlog_dir, ".iq")))

    axf_path = _find_axf([armlog_dir, root, armlog_dir.parent], explicit=axf)
    if axf_path is None:
        info.warnings.append("no .axf found; symbolize will be skipped")
        info.axf_match = None
    else:
        add(_entry("axf", axf_path, usable=True))
        from dumptrace.symbol_match import find_sibling_map

        map_path = find_sibling_map(axf_path, [armlog_dir, root, armlog_dir.parent])
        add(_entry("map", map_path, usable=True))
        if project_version:
            # 粗匹配保留在接入阶段；完整分项检查见 refine_symbol_match
            from dumptrace.symbol_match import version_token

            token = version_token(project_version)
            info.axf_match = bool(token and token.lower() in axf_path.name.lower())

    return info


def refine_symbol_match(
    info: PackageInfo,
    *,
    project_version: Optional[str],
    build_time: Optional[str],
) -> None:
    """ASS 解析后：文件名 / 编译时间 / Build ID / map 校验分项比对。"""
    from dumptrace.symbol_match import assess_symbol_match

    report = assess_symbol_match(
        axf=info.axf_path,
        map_path=info.map_path,
        project_version=project_version,
        build_time=build_time,
    )
    info.symbol_match = report.to_dict()
    info.axf_match = report.overall
    for w in report.warnings:
        if w not in info.warnings:
            info.warnings.append(w)


# 兼容旧名
def refine_axf_match(info: PackageInfo, project_version: Optional[str]) -> None:
    refine_symbol_match(info, project_version=project_version, build_time=None)


def parse_log_stat(path: Optional[Path]) -> Optional[Dict[str, str]]:
    if path is None or not path.is_file() or path.stat().st_size == 0:
        return None
    out: Dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out or None
