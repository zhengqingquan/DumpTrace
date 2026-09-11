# -*- coding: utf-8 -*-
"""解析 .ass 断言/异常现场。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AssertScene:
    assert_msg: Optional[str] = None
    exception_addr: Optional[str] = None
    fault_desc: Optional[str] = None
    dfsr: Optional[str] = None
    fault_addr: Optional[str] = None
    thread_id: Optional[str] = None
    thread_name: Optional[str] = None
    tcb_addr: Optional[str] = None
    queue_name: Optional[str] = None
    queue_total: Optional[int] = None
    queue_used: Optional[int] = None
    queue_available: Optional[int] = None
    stack_start: Optional[str] = None
    stack_end: Optional[str] = None
    mem_base: Optional[str] = None
    mem_size: Optional[int] = None
    regs: Dict[str, str] = field(default_factory=dict)
    mode_regs: Dict[str, Dict[str, str]] = field(default_factory=dict)
    project_version: Optional[str] = None
    platform_version: Optional[str] = None
    hw_version: Optional[str] = None
    build_time: Optional[str] = None
    mem_hints: List[str] = field(default_factory=list)
    excerpt: str = ""
    raw_text_len: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{6,}")


def extract_printable_text(data: bytes) -> str:
    parts = [m.group().decode("ascii", errors="ignore") for m in _PRINTABLE_RE.finditer(data)]
    # 用换行连接，便于按行正则；ASS 里字段常被空格拆开
    return "\n".join(parts)


def _first(pattern: str, text: str, flags: int = 0) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def _find_scene_window(text: str) -> str:
    """截取第一段完整异常现场，避免重复 dump 菜单干扰。"""
    markers = [
        "Exception at ",
        "ASSERT(",
        "Abort fault",
        "Current thread info:",
    ]
    starts = [text.find(m) for m in markers if text.find(m) >= 0]
    if not starts:
        return text[:8000]
    start = min(starts)
    # 尽量覆盖到 Assert Debug Menu 之前
    end_markers = ["Assert Debug Menu:", "=============== Dump All Memory"]
    end = len(text)
    for em in end_markers:
        i = text.find(em, start + 50)
        if i >= 0:
            end = min(end, i)
    window = text[start:end]
    # 若窗口太短，向后多取一点
    if len(window) < 400:
        window = text[start : start + 6000]
    return window


def parse_ass(path: Path) -> AssertScene:
    data = path.read_bytes()
    text = extract_printable_text(data)
    window = _find_scene_window(text)
    scene = AssertScene(raw_text_len=len(text), excerpt=window.strip())

    scene.assert_msg = _first(r"ASSERT\(([^)]+)\)", window) or _first(
        r"ASSERT\(([^)]+)\)", text
    )
    scene.exception_addr = _normalize_hex(
        _first(r"Exception at (0x[0-9A-Fa-f]+)", window)
        or _first(r"Exception at (0x[0-9A-Fa-f]+)", text)
    )
    fault_line = _first(
        r"(Abort fault\([^)]+\):[^\n]*)", window
    ) or _first(r"(Abort fault\([^)]+\):[^\n]*)", text)
    if fault_line:
        scene.fault_desc = fault_line.strip()
        scene.dfsr = _normalize_hex(_first(r"DFSR:(0x[0-9A-Fa-f]+)", fault_line))
    scene.fault_addr = _normalize_hex(
        _first(r"Fault address\s*:?\s*(0x[0-9A-Fa-f]+)", window, re.I)
        or _first(r"Fault address\s*:?\s*(0x[0-9A-Fa-f]+)", text, re.I)
    )

    scene.thread_id = _normalize_hex(
        _first(r"ID:\s*(0x[0-9A-Fa-f]+)", window)
    )
    scene.thread_name = _first(r"Name:\s*([A-Za-z0-9_]+)", window)
    scene.tcb_addr = _normalize_hex(_first(r"Tcb_Addr:\s*(0x[0-9A-Fa-f]+)", window))
    scene.queue_name = _first(r"Queue_Name:\s*([A-Za-z0-9_]+)", window)
    for attr, pat in (
        ("queue_total", r"Queue_Total:\s*(\d+)"),
        ("queue_used", r"Queue_Used:\s*(\d+)"),
        ("queue_available", r"Queue_Available:\s*(\d+)"),
    ):
        raw = _first(pat, window) or _first(pat, text)
        if raw is not None:
            try:
                setattr(scene, attr, int(raw))
            except ValueError:
                pass
    scene.stack_start = _normalize_hex(
        _first(r"Stack_Start:\s*(0x[0-9A-Fa-f]+)", window)
    )
    scene.stack_end = _normalize_hex(
        _first(r"Stack_End:\s*(0x[0-9A-Fa-f]+)", window)
    )

    # Memory Dumping Finished:begin addr=0x80000000,total size=29431680Byte
    mem_base = _first(
        r"begin addr\s*=\s*(0x[0-9A-Fa-f]+)", text, re.I
    ) or _first(r"Memory Dumping Finished:begin addr\s*=\s*(0x[0-9A-Fa-f]+)", text, re.I)
    scene.mem_base = _normalize_hex(mem_base)
    size_s = _first(r"total size\s*=\s*(\d+)\s*Byte", text, re.I)
    if size_s:
        try:
            scene.mem_size = int(size_s)
        except ValueError:
            scene.mem_size = None

    scene.project_version = _first(r"Project Version:\s*([^\n]+)", text)
    scene.platform_version = _first(r"Platform Version:\s*([^\n]+)", text)
    scene.hw_version = _first(r"HW Version:\s*([^\n]+)", text)
    # 日期行形如 10-10-2025 14:17:03
    scene.build_time = _first(
        r"(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})", text
    )

    scene.regs = _parse_current_regs(window) or _parse_current_regs(text)
    scene.mode_regs = _parse_mode_regs(window) or _parse_mode_regs(text)

    # 内存线索：filename.c(123)
    hints = []
    for m in re.finditer(r"([A-Za-z0-9_\-]+\.(?:c|cpp|s|h))\((\d+)\)", text):
        hint = f"{m.group(1)}:{m.group(2)}"
        if hint not in hints and (
            "mem" in m.group(1).lower()
            or "rvos" in m.group(1).lower()
            or "umem" in m.group(1).lower()
        ):
            hints.append(hint)
        if len(hints) >= 8:
            break
    # 也保留窗口开头附近的首个 .c(line)
    first_c = _first(r"([A-Za-z0-9_\-]+\.(?:c|cpp|s))\((\d+)\)", window)
    if first_c:
        # _first only returns group1; re-do
        m = re.search(r"([A-Za-z0-9_\-]+\.(?:c|cpp|s))\((\d+)\)", window)
        if m:
            h = f"{m.group(1)}:{m.group(2)}"
            if h not in hints:
                hints.insert(0, h)
    scene.mem_hints = hints

    return scene


def _normalize_hex(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().lower()
    if not v.startswith("0x"):
        v = "0x" + v
    try:
        return f"0x{int(v, 16):x}"
    except ValueError:
        return value.strip()


def _parse_current_regs(text: str) -> Dict[str, str]:
    regs: Dict[str, str] = {}
    # R0  = 0x00000000    R1   = 0x8097abc4
    for m in re.finditer(
        r"\b(R\d+|PC|LR|SPSR|CPSR)\s*=\s*(0x[0-9A-Fa-f]+)", text
    ):
        name = m.group(1).upper()
        if name == "R14":
            name = "LR"
        if name == "R13":
            name = "SP"
        if name not in regs:
            regs[name] = _normalize_hex(m.group(2)) or m.group(2)
    # 显式 PC / R14 行（Current mode 块）
    pc = _first(r"PC\s*=\s*(0x[0-9A-Fa-f]+)", text)
    r14 = _first(r"R14\s*=\s*(0x[0-9A-Fa-f]+)", text)
    if pc:
        regs["PC"] = _normalize_hex(pc) or pc
    if r14:
        regs.setdefault("LR", _normalize_hex(r14) or r14)
        regs["R14"] = _normalize_hex(r14) or r14
    return regs


def _parse_mode_regs(text: str) -> Dict[str, Dict[str, str]]:
    modes = ["SVC", "IRQ", "Abort", "Undefined", "FIQ"]
    out: Dict[str, Dict[str, str]] = {}
    for mode in modes:
        # > SVC mode: ... until next > Xxx mode or end
        pat = rf">\s*{mode}\s+mode:(.*?)(?=>\s*(?:SVC|IRQ|Abort|Undefined|FIQ)\s+mode:|Assert Debug Menu:|$)"
        m = re.search(pat, text, re.S | re.I)
        if not m:
            continue
        block = m.group(1)
        regs: Dict[str, str] = {}
        for rm in re.finditer(
            r"\b(R\d+|SPSR|CPSR)\s*=\s*(0x[0-9A-Fa-f]+)", block
        ):
            regs[rm.group(1).upper()] = _normalize_hex(rm.group(2)) or rm.group(2)
        if regs:
            out[mode] = regs
    return out


def addresses_for_symbolize(scene: AssertScene) -> List[Tuple[str, str]]:
    """返回 [(role, addr), ...]。"""
    items: List[Tuple[str, str]] = []
    pc = scene.regs.get("PC")
    if pc:
        items.append(("pc", pc))
    if scene.exception_addr:
        items.append(("exception", scene.exception_addr))
    lr = scene.regs.get("LR") or scene.regs.get("R14")
    if lr and lr != scene.exception_addr:
        items.append(("lr", lr))
    svc = scene.mode_regs.get("SVC", {})
    if svc.get("R14"):
        items.append(("svc_lr", svc["R14"]))
    # 去重保序
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for role, addr in items:
        key = (role, addr.lower())
        if key in seen:
            continue
        seen.add(key)
        uniq.append((role, addr))
    return uniq
