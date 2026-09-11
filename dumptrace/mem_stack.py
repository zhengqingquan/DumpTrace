# -*- coding: utf-8 -*-
"""从 .mem 按 ASS 栈区切片。"""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


DEFAULT_MEM_BASE = 0x80000000


@dataclass
class StackSlice:
    ok: bool
    mem_base: int
    stack_start: int
    stack_end: int
    file_offset: int
    length: int
    data: bytes = b""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("data", None)
        d["data_len"] = len(self.data)
        return d


def _parse_addr(s: Optional[str], default: Optional[int] = None) -> Optional[int]:
    if not s:
        return default
    try:
        return int(s, 16)
    except ValueError:
        return default


def extract_stack(
    mem_path: Path,
    *,
    stack_start: Optional[str],
    stack_end: Optional[str],
    mem_base: Optional[str] = None,
    default_base: int = DEFAULT_MEM_BASE,
) -> StackSlice:
    base = _parse_addr(mem_base, default_base)
    start = _parse_addr(stack_start)
    end = _parse_addr(stack_end)
    if base is None or start is None or end is None:
        return StackSlice(
            ok=False,
            mem_base=base or default_base,
            stack_start=start or 0,
            stack_end=end or 0,
            file_offset=0,
            length=0,
            error="missing stack_start/stack_end/mem_base",
        )
    if end < start:
        return StackSlice(
            ok=False,
            mem_base=base,
            stack_start=start,
            stack_end=end,
            file_offset=0,
            length=0,
            error="stack_end < stack_start",
        )

    offset = start - base
    length = end - start + 1
    if offset < 0:
        return StackSlice(
            ok=False,
            mem_base=base,
            stack_start=start,
            stack_end=end,
            file_offset=offset,
            length=length,
            error=f"stack_start {hex(start)} below mem_base {hex(base)}",
        )

    try:
        size = mem_path.stat().st_size
    except OSError as e:
        return StackSlice(
            ok=False,
            mem_base=base,
            stack_start=start,
            stack_end=end,
            file_offset=offset,
            length=length,
            error=str(e),
        )

    if offset + length > size:
        length = max(0, size - offset)
        if length <= 0:
            return StackSlice(
                ok=False,
                mem_base=base,
                stack_start=start,
                stack_end=end,
                file_offset=offset,
                length=0,
                error="stack range outside mem file",
            )

    with mem_path.open("rb") as f:
        f.seek(offset)
        data = f.read(length)

    return StackSlice(
        ok=True,
        mem_base=base,
        stack_start=start,
        stack_end=end,
        file_offset=offset,
        length=len(data),
        data=data,
    )


def write_stack_files(out_dir: Path, slice_: StackSlice) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not slice_.ok:
        note = out_dir / "stack_error.txt"
        note.write_text(slice_.error or "stack extract failed", encoding="utf-8")
        return [note]

    bin_path = out_dir / "stack.bin"
    hex_path = out_dir / "stack.hex"
    bin_path.write_bytes(slice_.data)

    lines = [
        f"; stack {hex(slice_.stack_start)}-{hex(slice_.stack_end)} "
        f"base={hex(slice_.mem_base)} file_off={hex(slice_.file_offset)} "
        f"len={slice_.length}",
    ]
    addr = slice_.stack_start
    data = slice_.data
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        lines.append(f"{addr:08X}  {hex_bytes}")
        addr += len(chunk)
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [bin_path, hex_path]


def scan_stack_words(
    data: bytes,
    *,
    stack_start: int,
    code_ranges: Sequence[Tuple[int, int]],
) -> List[Tuple[int, int]]:
    """扫描小端 u32，返回 [(stack_addr, value_cleared_thumb), ...]。"""
    out: List[Tuple[int, int]] = []
    seen = set()
    n = len(data) // 4 * 4
    for i in range(0, n, 4):
        (val,) = struct.unpack_from("<I", data, i)
        cleared = val & ~1
        if cleared in seen:
            continue
        if not any(lo <= cleared <= hi for lo, hi in code_ranges):
            continue
        seen.add(cleared)
        out.append((stack_start + i, cleared))
    return out
