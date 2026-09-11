# -*- coding: utf-8 -*-
"""从 .mem 提取 Fault/指针地址附近的十六进制窗口（不做完整堆遍历）。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dumptrace.mem_stack import DEFAULT_MEM_BASE, _parse_addr


@dataclass
class MemWindowSlice:
    role: str
    addr: int
    center: int
    before: int
    after: int
    mem_base: int
    file_offset: int
    length: int
    data: bytes = b""
    ok: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("data", None)
        d["data_len"] = len(self.data)
        d["addr_hex"] = hex(self.addr)
        d["center_hex"] = hex(self.center)
        return d


@dataclass
class MemWindowReport:
    ok: bool
    windows: List[MemWindowSlice] = field(default_factory=list)
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    skipped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "skipped": self.skipped,
            "overall": dict(self.overall),
            "windows": [w.to_dict() for w in self.windows],
            "warnings": list(self.warnings),
        }


def _in_file_range(addr: int, base: int, size: int) -> bool:
    off = addr - base
    return 0 <= off < size


def _extract_one(
    mem_path: Path,
    *,
    role: str,
    addr: int,
    mem_base: int,
    before: int,
    after: int,
    file_size: int,
) -> MemWindowSlice:
    if addr < 0:
        return MemWindowSlice(
            role=role,
            addr=addr,
            center=addr,
            before=before,
            after=after,
            mem_base=mem_base,
            file_offset=0,
            length=0,
            error="invalid address",
        )
    start = max(mem_base, addr - before)
    end = min(mem_base + file_size - 1, addr + after)
    if end < start:
        return MemWindowSlice(
            role=role,
            addr=addr,
            center=addr,
            before=before,
            after=after,
            mem_base=mem_base,
            file_offset=addr - mem_base,
            length=0,
            error=f"address {hex(addr)} outside mem [{hex(mem_base)}, {hex(mem_base + file_size)})",
        )
    if not _in_file_range(addr, mem_base, file_size):
        return MemWindowSlice(
            role=role,
            addr=addr,
            center=addr,
            before=before,
            after=after,
            mem_base=mem_base,
            file_offset=addr - mem_base,
            length=0,
            error=f"address {hex(addr)} outside mem file",
        )
    offset = start - mem_base
    length = end - start + 1
    with mem_path.open("rb") as f:
        f.seek(offset)
        data = f.read(length)
    return MemWindowSlice(
        role=role,
        addr=addr,
        center=addr,
        before=before,
        after=after,
        mem_base=mem_base,
        file_offset=offset,
        length=len(data),
        data=data,
        ok=True,
    )


def _collect_targets(
    *,
    fault_addr: Optional[str],
    regs: Optional[Dict[str, str]],
    mem_base: int,
    file_size: int,
    extra_addrs: Optional[Sequence[Tuple[str, str]]] = None,
) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    seen = set()

    def add(role: str, raw: Optional[str]) -> None:
        if not raw:
            return
        v = _parse_addr(raw)
        if v is None:
            return
        if v in seen:
            return
        seen.add(v)
        out.append((role, v))

    add("fault", fault_addr)
    if regs:
        for key in ("R0", "R1", "R2", "R3", "PC", "LR", "R13_SVC", "R14_SVC"):
            add(key.lower(), regs.get(key))
    if extra_addrs:
        for role, raw in extra_addrs:
            add(role, raw)

    # 过滤明显空页指针（仍保留 fault 以便报告 outside/null）
    filtered: List[Tuple[str, int]] = []
    for role, addr in out:
        if role == "fault":
            filtered.append((role, addr))
            continue
        # 仅保留落在 mem 映射内的寄存器指针，避免噪声
        if _in_file_range(addr, mem_base, file_size):
            filtered.append((role, addr))
    return filtered


def extract_mem_windows(
    mem_path: Path,
    *,
    fault_addr: Optional[str] = None,
    regs: Optional[Dict[str, str]] = None,
    mem_base: Optional[str] = None,
    window_bytes: int = 256,
    default_base: int = DEFAULT_MEM_BASE,
    extra_addrs: Optional[Sequence[Tuple[str, str]]] = None,
) -> MemWindowReport:
    """
    以 center 为中心取前后各 window_bytes//2 字节（默认共 256B）。
    Fault 不在映射内时记入 warnings，不中止。
    """
    if window_bytes < 16:
        window_bytes = 16
    half = window_bytes // 2
    base = _parse_addr(mem_base, default_base) or default_base

    try:
        size = mem_path.stat().st_size
    except OSError as e:
        return MemWindowReport(ok=False, warnings=[str(e)])

    if size <= 0:
        return MemWindowReport(
            ok=False, skipped=True, warnings=["mem file empty"], overall={"mem_size": 0}
        )

    targets = _collect_targets(
        fault_addr=fault_addr,
        regs=regs,
        mem_base=base,
        file_size=size,
        extra_addrs=extra_addrs,
    )
    if not targets:
        return MemWindowReport(
            ok=False,
            skipped=True,
            warnings=["no fault/register addresses to window"],
            overall={"mem_size": size, "mem_base": hex(base)},
        )

    report = MemWindowReport(ok=False, overall={"mem_size": size, "mem_base": hex(base)})
    for role, addr in targets:
        w = _extract_one(
            mem_path,
            role=role,
            addr=addr,
            mem_base=base,
            before=half,
            after=half - 1 if window_bytes % 2 == 0 else half,
            file_size=size,
        )
        report.windows.append(w)
        if not w.ok and w.error:
            report.warnings.append(f"{role}@{hex(addr)}: {w.error}")

    ok_n = sum(1 for w in report.windows if w.ok)
    report.overall.update(
        {
            "requested": len(targets),
            "ok_count": ok_n,
            "window_bytes": window_bytes,
        }
    )
    report.ok = ok_n > 0
    if ok_n == 0:
        report.skipped = False  # 尝试过但全部失败
    return report


def render_mem_window_hex(report: MemWindowReport) -> str:
    lines = [
        f"# mem_window ok={report.ok} skipped={report.skipped} "
        f"base={report.overall.get('mem_base')} size={report.overall.get('mem_size')}",
    ]
    for w in report.windows:
        lines.append("")
        if not w.ok:
            lines.append(f"; [{w.role}] {hex(w.addr)} ERROR {w.error}")
            continue
        lines.append(
            f"; [{w.role}] center={hex(w.center)} "
            f"file_off={hex(w.file_offset)} len={w.length}"
        )
        addr = w.mem_base + w.file_offset
        data = w.data
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            marker = " <<" if addr <= w.center < addr + len(chunk) else ""
            lines.append(f"{addr:08X}  {hex_bytes}{marker}")
            addr += len(chunk)
    if report.warnings:
        lines += ["", "; warnings"]
        lines.extend(f"; {w}" for w in report.warnings)
    return "\n".join(lines) + "\n"


def render_mem_window_txt(report: MemWindowReport) -> str:
    lines = [
        f"# mem_window ok={report.ok} skipped={report.skipped}",
        f"overall={report.overall}",
        "",
    ]
    for w in report.windows:
        lines.append(
            f"- {w.role}: addr={hex(w.addr)} ok={w.ok} "
            f"len={w.length} err={w.error or ''}"
        )
    if report.warnings:
        lines += ["", "## warnings"]
        lines.extend(f"- {w}" for w in report.warnings)
    lines.append("")
    lines.append("详见 mem_window.hex")
    return "\n".join(lines) + "\n"
