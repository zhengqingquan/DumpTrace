# -*- coding: utf-8 -*-
"""从 .ass 解析内存池 / 空间段 / 分配表使用情况。"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOP_N = 15

_PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{4,}")


def _extract_text(data: bytes) -> str:
    """内存表里 ALLOC/FREE 常单独成行（4~5 字符），需比通用 ASS 提取更短阈值。"""
    parts = [m.group().decode("ascii", errors="ignore") for m in _PRINTABLE_RE.finditer(data)]
    return "\n".join(parts)

_POOL_HEADER_RE = re.compile(
    r"={3,}\s*([A-Za-z0-9 ]+?Space Information)\s*={3,}",
    re.I,
)
# 专用池：电话本 / 字库 cache 等（非 System/Static Space）
_DEDICATED_POOL_HEADER_RE = re.compile(
    r"={3,}\s*([A-Za-z0-9_ ]+?(?:POOL|Pool|cache|Cache) Information)\s*={3,}",
    re.I,
)
_POOL_SUMMARY_RE = re.compile(
    r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)",
    re.I,
)
# 无 Threshold 列的专用池汇总
_POOL_SUMMARY_5_RE = re.compile(
    r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\b",
    re.I,
)
_SEGMENT_RE = re.compile(
    r"-{5,}([A-Za-z0-9 ]+?)-{5,}\s*"
    r"---Base Addr:(0x[0-9A-Fa-f]+),\s*End Addr:(0x[0-9A-Fa-f]+),\s*"
    r"Length:(\d+),\s*Type:(\w+)----",
    re.I,
)
_BLOCK_RE = re.compile(
    r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s+"
    r"(ALLOC|FREE)\s+"
    r"(\(\d+\)|[A-Za-z_][A-Za-z0-9_\.\-]*\([^)]*\)|[A-Za-z_][A-Za-z0-9_\.\-]*\.(?:c|cpp|h|s))",
    re.I,
)
_ALLOC_INFO_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+([A-Za-z0-9_\.\-]+\.(?:c|cpp|h|s))\s+"
    r"\(Line\s+(\d+)\),addr:([0-9A-Fa-f]+)",
    re.I | re.M,
)


@dataclass
class PoolSummary:
    name: str
    begin: Optional[str] = None
    end: Optional[str] = None
    total: int = 0
    avail: int = 0
    max_used: int = 0
    threshold: int = 0
    used: int = 0
    used_pct: Optional[float] = None
    kind: str = "main"  # main / dedicated

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileUsage:
    file: str
    bytes: int
    blocks: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SegmentSummary:
    space: str
    title: str
    base: str
    end: str
    length: int
    type: str
    alloc_bytes: int = 0
    free_bytes: int = 0
    alloc_blocks: int = 0
    free_blocks: int = 0
    largest_free: int = 0
    top_files: List[FileUsage] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["top_files"] = [f.to_dict() for f in self.top_files]
        return d


@dataclass
class AllocEntry:
    no: int
    size: int
    file: str
    line: int
    addr: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MemUsageReport:
    ok: bool
    pools: List[PoolSummary] = field(default_factory=list)
    segments: List[SegmentSummary] = field(default_factory=list)
    overall: Dict[str, Any] = field(default_factory=dict)
    allocated_info: Dict[str, Any] = field(default_factory=dict)
    largest_free_blocks: List[Dict[str, Any]] = field(default_factory=list)
    leak_suspects: List[Dict[str, Any]] = field(default_factory=list)
    fragmentation: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "overall": self.overall,
            "pools": [p.to_dict() for p in self.pools],
            "segments": [s.to_dict() for s in self.segments],
            "allocated_info": self.allocated_info,
            "largest_free_blocks": list(self.largest_free_blocks),
            "leak_suspects": list(self.leak_suspects),
            "fragmentation": dict(self.fragmentation),
            "warnings": list(self.warnings),
        }


def _norm_blocks_text(text: str) -> str:
    """把被可打印切分拆开的 Size/ALLOC/file 行拼回一行。"""
    text = re.sub(
        r"(\d+)\s*\n\s*(ALLOC|FREE)\s*\n\s*([^\n]+)",
        r"\1 \2 \3",
        text,
        flags=re.I,
    )
    text = re.sub(
        r"(\d+)\s+(ALLOC|FREE)\s*\n\s*([^\n]+)",
        r"\1 \2 \3",
        text,
        flags=re.I,
    )
    # FREE/ALLOC 后无文件名、下一行直接是地址或结束
    text = re.sub(
        r"(\d+)\s*\n\s*(ALLOC|FREE)\s*(?=\n\s*0x|\n\s*-{3,}|\n\s*={3,}|\s*\Z)",
        r"\1 \2 (0)",
        text,
        flags=re.I,
    )
    return text


def _pct(used: int, total: int) -> Optional[float]:
    if total <= 0:
        return None
    return round(100.0 * used / total, 2)


def _top_files(counter_bytes: Dict[str, int], counter_blocks: Dict[str, int], n: int = TOP_N) -> List[FileUsage]:
    items = sorted(counter_bytes.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return [
        FileUsage(file=name, bytes=sz, blocks=counter_blocks.get(name, 0))
        for name, sz in items
        if name and name not in ("(0)", "0")
    ]


def parse_mem_usage(
    path: Path, *, assert_msg: Optional[str] = None
) -> MemUsageReport:
    try:
        data = path.read_bytes()
    except OSError as e:
        return MemUsageReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _norm_blocks_text(_extract_text(data))
    report = MemUsageReport(ok=False)

    report.pools = _parse_pools(text)
    report.segments = _parse_segments(text)
    report.allocated_info = _parse_allocated_info(text)
    report.largest_free_blocks = _largest_free(text, limit=10)

    main_pools = [p for p in report.pools if p.kind == "main"]
    dedicated = [p for p in report.pools if p.kind == "dedicated"]
    if main_pools:
        total = sum(p.total for p in main_pools)
        avail = sum(p.avail for p in main_pools)
        used = sum(p.used for p in main_pools)
        report.overall = {
            "total": total,
            "avail": avail,
            "used": used,
            "used_pct": _pct(used, total),
            "pool_count": len(main_pools),
            "dedicated_pool_count": len(dedicated),
            "segment_count": len(report.segments),
            "source": "space_summary",
        }
    elif report.pools:
        # 仅有专用池
        total = sum(p.total for p in report.pools)
        avail = sum(p.avail for p in report.pools)
        used = sum(p.used for p in report.pools)
        report.overall = {
            "total": total,
            "avail": avail,
            "used": used,
            "used_pct": _pct(used, total),
            "pool_count": 0,
            "dedicated_pool_count": len(report.pools),
            "segment_count": len(report.segments),
            "source": "dedicated_pools_only",
        }
    elif report.segments:
        total = sum(s.length for s in report.segments)
        avail = sum(s.free_bytes for s in report.segments)
        used = sum(s.alloc_bytes for s in report.segments)
        report.overall = {
            "total": total,
            "avail": avail,
            "used": used,
            "used_pct": _pct(used, total),
            "pool_count": 0,
            "segment_count": len(report.segments),
            "source": "segment_blocks",
        }
    elif report.allocated_info.get("count"):
        report.overall = {
            "total": None,
            "avail": None,
            "used": report.allocated_info.get("total_bytes"),
            "used_pct": None,
            "pool_count": 0,
            "segment_count": 0,
            "source": "allocated_info_only",
        }
        report.warnings.append(
            "only Allocated memory info found; no System/Static Space summary"
        )
    else:
        report.warnings.append("no memory usage tables found in .ass")
        return report

    report.leak_suspects = _build_leak_suspects(report)
    report.fragmentation = _build_fragmentation(report, assert_msg=assert_msg)

    report.ok = True
    if report.overall.get("used_pct") is not None and report.overall["used_pct"] >= 95:
        report.warnings.append(
            f"memory pressure high: used_pct={report.overall['used_pct']}%"
        )
    return report


_ALLOC_SIZE_RE = re.compile(
    r"(?:size|bytes?|alloc(?:ate)?)\s*[=:]?\s*(\d+)",
    re.I,
)


def _extract_assert_alloc_size(assert_msg: Optional[str]) -> Optional[int]:
    if not assert_msg:
        return None
    m = _ALLOC_SIZE_RE.search(assert_msg)
    if m:
        return int(m.group(1))
    # 纯数字兜底：unable to allocate, 1024
    m2 = re.search(r"allocate[^\d]{0,20}(\d{2,})", assert_msg, re.I)
    if m2:
        return int(m2.group(1))
    return None


def _build_leak_suspects(report: MemUsageReport, top_n: int = 10) -> List[Dict[str, Any]]:
    """同文件多块 + 高占比 → 泄漏嫌疑分。"""
    file_bytes: Dict[str, int] = defaultdict(int)
    file_blocks: Dict[str, int] = defaultdict(int)
    ai = report.allocated_info or {}
    for f in ai.get("top_files") or []:
        file_bytes[f["file"]] += int(f.get("bytes") or 0)
        file_blocks[f["file"]] += int(f.get("blocks") or 0)
    for s in report.segments:
        for f in s.top_files:
            file_bytes[f.file] += f.bytes
            file_blocks[f.file] += f.blocks
    total = sum(file_bytes.values()) or 1
    suspects: List[Dict[str, Any]] = []
    for name, nbytes in file_bytes.items():
        blocks = file_blocks.get(name, 0)
        share = round(100.0 * nbytes / total, 2)
        # 多块加权 + 占比
        score = round(share + min(40.0, blocks * 2.0), 2)
        if blocks < 2 and share < 5:
            continue
        suspects.append(
            {
                "file": name,
                "bytes": nbytes,
                "blocks": blocks,
                "share_pct": share,
                "score": score,
            }
        )
    suspects.sort(key=lambda x: (-x["score"], -x["bytes"]))
    return suspects[:top_n]


def _build_fragmentation(
    report: MemUsageReport, *, assert_msg: Optional[str]
) -> Dict[str, Any]:
    largest = 0
    if report.largest_free_blocks:
        largest = int(report.largest_free_blocks[0].get("size") or 0)
    elif report.segments:
        largest = max((s.largest_free for s in report.segments), default=0)
    alloc_size = _extract_assert_alloc_size(assert_msg)
    hint = None
    if alloc_size is not None and largest > 0:
        if alloc_size > largest:
            hint = (
                f"申请 size={alloc_size} 大于最大空闲块 {largest}，"
                f"更像真 OOM/碎片不足（而非单纯水位高）"
            )
        else:
            hint = (
                f"申请 size={alloc_size} ≤ 最大空闲块 {largest}，"
                f"若仍分配失败需查对齐/专用池/并发"
            )
    elif largest > 0 and report.overall.get("avail") is not None:
        avail = int(report.overall.get("avail") or 0)
        if avail > 0 and largest < avail * 0.1:
            hint = (
                f"最大空闲块 {largest} 远小于 avail={avail}，存在明显碎片化嫌疑"
            )
    return {
        "largest_free": largest,
        "assert_alloc_size": alloc_size,
        "hint": hint,
    }


def _parse_pools(text: str) -> List[PoolSummary]:
    """解析带 Total_Num / Avail_Num / Max_Used 的空间汇总行（含专用池）。"""
    pools: List[PoolSummary] = []
    seen_ranges: set = set()

    def _add_from_headers(headers: List[re.Match], kind: str) -> None:
        for i, hm in enumerate(headers):
            name = re.sub(r"\s+", " ", hm.group(1)).strip()
            start = hm.end()
            end = (
                headers[i + 1].start()
                if i + 1 < len(headers)
                else min(len(text), start + 4000)
            )
            window = text[start:end]
            if "Total_Num" not in window and "Avail_Num" not in window:
                continue
            sm6 = _POOL_SUMMARY_RE.search(window)
            sm5 = None if sm6 else _POOL_SUMMARY_5_RE.search(window)
            sm = sm6 or sm5
            if not sm:
                continue
            begin = sm.group(1).lower()
            end_addr = sm.group(2).lower()
            key = (begin, end_addr, name.lower())
            if key in seen_ranges:
                continue
            seen_ranges.add(key)
            total = int(sm.group(3))
            avail = int(sm.group(4))
            max_used = int(sm.group(5))
            threshold = int(sm.group(6)) if sm6 else 0
            used = max(0, total - avail)
            # 仅 System/Static 计入主池 overall；其余 Space/POOL/cache 均作专用
            nlow = name.lower()
            if "system space" in nlow or "static space" in nlow:
                resolved_kind = "main"
            else:
                resolved_kind = "dedicated"
            pools.append(
                PoolSummary(
                    name=name,
                    begin=begin,
                    end=end_addr,
                    total=total,
                    avail=avail,
                    max_used=max_used,
                    threshold=threshold,
                    used=used,
                    used_pct=_pct(used, total),
                    kind=resolved_kind,
                )
            )

    _add_from_headers(list(_POOL_HEADER_RE.finditer(text)), "main")
    _add_from_headers(list(_DEDICATED_POOL_HEADER_RE.finditer(text)), "dedicated")
    return pools


def _space_name_near(text: str, pos: int) -> str:
    prev = list(_POOL_HEADER_RE.finditer(text[: pos + 1]))
    if not prev:
        return "Unknown Space"
    return re.sub(r"\s+", " ", prev[-1].group(1)).strip()


def _parse_segments(text: str) -> List[SegmentSummary]:
    segs: List[SegmentSummary] = []
    matches = list(_SEGMENT_RE.finditer(text))
    for i, m in enumerate(matches):
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        base, end, length_s, typ = m.group(2).lower(), m.group(3).lower(), m.group(4), m.group(5)
        length = int(length_s)
        body_start = m.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else min(len(text), body_start + 200000)
        # 截到下一个 Space Information 之前
        nxt_space = _POOL_HEADER_RE.search(text, body_start)
        if nxt_space and nxt_space.start() < body_end:
            body_end = nxt_space.start()
        body = text[body_start:body_end]
        alloc_b = free_b = alloc_n = free_n = largest_free = 0
        file_bytes: Dict[str, int] = defaultdict(int)
        file_blocks: Dict[str, int] = defaultdict(int)
        for bm in _BLOCK_RE.finditer(body):
            size = int(bm.group(3))
            state = bm.group(4).upper()
            fname = bm.group(5).strip()
            # 去掉尾部垃圾
            fname = re.split(r"[\s,]", fname, maxsplit=1)[0]
            if state == "ALLOC":
                alloc_b += size
                alloc_n += 1
                # file(line) → file
                file_key = fname.split("(")[0] if "(" in fname else fname
                file_bytes[file_key] += size
                file_blocks[file_key] += 1
            else:
                free_b += size
                free_n += 1
                if size > largest_free:
                    largest_free = size
        # 若块字节和与 length 差很多，仍保留解析结果
        segs.append(
            SegmentSummary(
                space=_space_name_near(text, m.start()),
                title=title,
                base=base,
                end=end,
                length=length,
                type=typ,
                alloc_bytes=alloc_b,
                free_bytes=free_b,
                alloc_blocks=alloc_n,
                free_blocks=free_n,
                largest_free=largest_free,
                top_files=_top_files(file_bytes, file_blocks, n=8),
            )
        )
    return segs


def _parse_allocated_info(text: str) -> Dict[str, Any]:
    marker = text.find("Allocated memory info:")
    if marker < 0:
        return {}
    # 截到 System/Static Space 或文件较远处
    end_m = _POOL_HEADER_RE.search(text, marker)
    end = end_m.start() if end_m else min(len(text), marker + 500000)
    block = text[marker:end]
    entries: List[AllocEntry] = []
    file_bytes: Dict[str, int] = defaultdict(int)
    file_blocks: Dict[str, int] = defaultdict(int)
    for m in _ALLOC_INFO_RE.finditer(block):
        ent = AllocEntry(
            no=int(m.group(1)),
            size=int(m.group(2)),
            file=m.group(3),
            line=int(m.group(4)),
            addr="0x" + m.group(5).lower(),
        )
        entries.append(ent)
        file_bytes[ent.file] += ent.size
        file_blocks[ent.file] += 1
    if not entries:
        return {}
    top_entries = sorted(entries, key=lambda e: -e.size)[:TOP_N]
    return {
        "count": len(entries),
        "total_bytes": sum(e.size for e in entries),
        "top_entries": [e.to_dict() for e in top_entries],
        "top_files": [f.to_dict() for f in _top_files(file_bytes, file_blocks)],
    }


def _largest_free(text: str, limit: int = 10) -> List[Dict[str, Any]]:
    frees: List[Tuple[int, str, str, str]] = []
    for m in _BLOCK_RE.finditer(text):
        if m.group(4).upper() != "FREE":
            continue
        size = int(m.group(3))
        frees.append((size, m.group(1).lower(), m.group(2).lower(), m.group(5)))
    frees.sort(key=lambda x: -x[0])
    out = []
    for size, start, end, tag in frees[:limit]:
        out.append({"size": size, "start": start, "end": end, "tag": tag})
    return out


def render_mem_usage_txt(report: MemUsageReport) -> str:
    lines = [
        f"# mem usage ok={report.ok}",
        f"# overall={report.overall}",
    ]
    for w in report.warnings:
        lines.append(f"# warn: {w}")
    lines += ["", "## pools"]
    if not report.pools:
        lines.append("(none)")
    for p in report.pools:
        lines.append(
            f"- [{p.kind}] {p.name}: total={p.total} used={p.used} avail={p.avail} "
            f"max_used={p.max_used} threshold={p.threshold} used_pct={p.used_pct} "
            f"range={p.begin}-{p.end}"
        )
    lines += ["", "## segments"]
    if not report.segments:
        lines.append("(none)")
    for s in report.segments:
        lines.append(
            f"- [{s.space}] {s.title}: len={s.length} alloc={s.alloc_bytes}/{s.alloc_blocks}b "
            f"free={s.free_bytes}/{s.free_blocks}b largest_free={s.largest_free} "
            f"type={s.type} {s.base}-{s.end}"
        )
        for f in s.top_files[:5]:
            lines.append(f"    file {f.file}: bytes={f.bytes} blocks={f.blocks}")
    lines += ["", "## allocated_info top_files"]
    ai = report.allocated_info or {}
    if not ai:
        lines.append("(none)")
    else:
        lines.append(f"count={ai.get('count')} total_bytes={ai.get('total_bytes')}")
        for f in ai.get("top_files") or []:
            lines.append(f"- {f.get('file')}: bytes={f.get('bytes')} blocks={f.get('blocks')}")
    lines += ["", "## largest_free_blocks"]
    if not report.largest_free_blocks:
        lines.append("(none)")
    for b in report.largest_free_blocks:
        lines.append(
            f"- size={b.get('size')} {b.get('start')}-{b.get('end')} tag={b.get('tag')}"
        )
    lines += ["", "## leak_suspects"]
    if not report.leak_suspects:
        lines.append("(none)")
    for s in report.leak_suspects:
        lines.append(
            f"- {s.get('file')}: bytes={s.get('bytes')} blocks={s.get('blocks')} "
            f"share={s.get('share_pct')}% score={s.get('score')}"
        )
    lines += ["", "## fragmentation"]
    if not report.fragmentation:
        lines.append("(none)")
    else:
        lines.append(str(report.fragmentation))
    return "\n".join(lines) + "\n"
