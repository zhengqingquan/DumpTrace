# -*- coding: utf-8 -*-
"""地址 → 符号反查（addr2line / fromelf 兜底说明）。"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass
class SymbolInfo:
    role: str
    addr: str
    func: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    tool: Optional[str] = None
    ok: bool = False
    raw: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        loc = ""
        if self.file:
            loc = self.file
            if self.line:
                loc = f"{loc}:{self.line}"
        parts = [p for p in [self.func, loc] if p]
        return " @ ".join(parts) if parts else "??"


def _which_addr2line(explicit: Optional[Path] = None) -> Optional[Path]:
    if explicit is not None:
        p = explicit.expanduser().resolve()
        return p if p.is_file() else None
    env = os.environ.get("DUMPTRACE_ADDR2LINE")
    if env:
        p = Path(env)
        if p.is_file():
            return p
    for name in (
        "arm-none-eabi-addr2line",
        "llvm-addr2line",
        "addr2line",
    ):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _clear_thumb_bit(addr: int) -> int:
    return addr & ~1


def _parse_addr(addr: str) -> int:
    return int(addr, 16)


def symbolize_addresses(
    axf: Path,
    items: Sequence[Tuple[str, str]],
    *,
    addr2line: Optional[Path] = None,
    timeout: float = 60.0,
) -> Tuple[List[SymbolInfo], List[str]]:
    """
    批量反查。返回 (symbols, warnings)。
    无工具时 ok=False，不抛异常（由上层决定退出码）。
    """
    warnings: List[str] = []
    tool = _which_addr2line(addr2line)
    if tool is None:
        warnings.append(
            "addr2line not found; set DUMPTRACE_ADDR2LINE or install GNU/LLVM addr2line"
        )
        return [
            SymbolInfo(role=role, addr=addr, ok=False, raw="tool missing")
            for role, addr in items
        ], warnings

    results: List[SymbolInfo] = []
    # 一次调用多地址
    addrs_num = []
    for role, addr in items:
        try:
            addrs_num.append((role, addr, _clear_thumb_bit(_parse_addr(addr))))
        except ValueError:
            results.append(
                SymbolInfo(role=role, addr=addr, ok=False, raw="bad address", tool=str(tool))
            )

    if not addrs_num:
        return results, warnings

    cmd = [str(tool), "-e", str(axf), "-f", "-C", "-a"] + [
        f"0x{a:x}" for _, _, a in addrs_num
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        warnings.append(f"addr2line failed: {e}")
        for role, addr, _ in addrs_num:
            results.append(
                SymbolInfo(role=role, addr=addr, ok=False, raw=str(e), tool=str(tool))
            )
        return results, warnings

    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    parsed = _parse_addr2line_output(out, addrs_num, str(tool))
    results.extend(parsed)
    if proc.returncode != 0 and not any(s.ok for s in parsed):
        warnings.append(f"addr2line exit={proc.returncode}")
    return results, warnings


def _parse_addr2line_output(
    output: str,
    addrs_num: List[Tuple[str, str, int]],
    tool: str,
) -> List[SymbolInfo]:
    """
    典型输出块：
      0x60022f48
      __tx_abort_handler
      path/file.s:1142
    """
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    blocks: List[List[str]] = []
    cur: List[str] = []
    for ln in lines:
        if ln.lower().startswith("0x") and cur:
            blocks.append(cur)
            cur = [ln]
        else:
            cur.append(ln)
    if cur:
        blocks.append(cur)

    by_addr: Dict[int, SymbolInfo] = {}
    for block in blocks:
        if not block:
            continue
        try:
            addr_v = int(block[0], 16)
        except ValueError:
            continue
        func = block[1] if len(block) > 1 else None
        file_line = block[2] if len(block) > 2 else None
        file_path = None
        line_no = None
        if file_line and file_line != "??" and ":" in file_line:
            # Windows path may contain drive letter C:
            if file_line[1:3] == ":\\" or file_line[1:3] == ":/":
                # split from rightmost :digits
                m_idx = file_line.rfind(":")
                file_path = file_line[:m_idx]
                try:
                    line_no = int(file_line[m_idx + 1 :])
                except ValueError:
                    file_path = file_line
            else:
                file_path, _, ln = file_line.rpartition(":")
                try:
                    line_no = int(ln)
                except ValueError:
                    file_path = file_line
        ok = bool(func and func not in ("??", "??:0", ""))
        if file_path in ("??", "??:0"):
            file_path = None
        by_addr[addr_v] = SymbolInfo(
            role="",
            addr=f"0x{addr_v:x}",
            func=None if func in (None, "??") else func,
            file=file_path,
            line=line_no,
            tool=tool,
            ok=ok,
            raw="\n".join(block),
        )

    results: List[SymbolInfo] = []
    for role, addr, num in addrs_num:
        info = by_addr.get(num)
        if info is None:
            results.append(
                SymbolInfo(role=role, addr=addr, ok=False, tool=tool, raw="no output")
            )
        else:
            results.append(
                SymbolInfo(
                    role=role,
                    addr=addr,
                    func=info.func,
                    file=info.file,
                    line=info.line,
                    tool=tool,
                    ok=info.ok,
                    raw=info.raw,
                )
            )
    return results
