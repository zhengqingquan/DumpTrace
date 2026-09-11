# -*- coding: utf-8 -*-
"""从 .ass 解析 MMI / UI 句柄树状态（P1）。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MmiNode:
    node_type: str  # APPLET / WINDOW / CTRL
    addr: Optional[str] = None
    handle: Optional[str] = None
    parent_handle: Optional[str] = None
    parent_tree_handle: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    source: str = "handle_list"  # handle_list / zorder

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MmiLayer:
    block_id: Optional[int] = None
    is_bltlayer: Optional[int] = None
    size: Optional[int] = None
    name: Optional[str] = None
    line: Optional[int] = None
    image_info: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MmiStateReport:
    ok: bool
    applets: List[MmiNode] = field(default_factory=list)
    windows: List[MmiNode] = field(default_factory=list)
    controls: List[MmiNode] = field(default_factory=list)
    zorder: List[MmiNode] = field(default_factory=list)
    layers: List[MmiLayer] = field(default_factory=list)
    focus_window: Optional[Dict[str, Any]] = None
    current_applet: Optional[Dict[str, Any]] = None
    anim_controls: List[Dict[str, Any]] = field(default_factory=list)
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "overall": self.overall,
            "current_applet": self.current_applet,
            "focus_window": self.focus_window,
            "anim_controls": list(self.anim_controls),
            "applets": [n.to_dict() for n in self.applets],
            "windows": [n.to_dict() for n in self.windows],
            "controls": [n.to_dict() for n in self.controls],
            "zorder": [n.to_dict() for n in self.zorder],
            "layers": [n.to_dict() for n in self.layers],
            "warnings": list(self.warnings),
        }


_NODE_RE = re.compile(
    r"\((MMI_(APPLET|WINDOW|CTRL)_NODE_T\*)\)\s*(0x[0-9A-Fa-f]+)\s*,\s*"
    r"handle=(0x[0-9A-Fa-f]+)\s*,\s*"
    r"parent_tree_handle=(0x[0-9A-Fa-f]+)\s*,\s*"
    r"parent_handle=(0x[0-9A-Fa-f]+)\s*,\s*"
    r"id=(0x[0-9A-Fa-f]+)\s*,\s*"
    r"name=([A-Za-z0-9_]+)",
    re.I,
)
_LAYER_RE = re.compile(
    r"block_id=(\d+)\s*,\s*is_bltlayer=(\d+)\s*,\s*size=(\d+)\s*,\s*"
    r"name=([A-Za-z0-9_\.\-]+)\s*,\s*line=(\d+)",
    re.I,
)
_IMAGE_RE = re.compile(r"data\.image\s+([^\n]+)", re.I)


def _normalize(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "").replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    return text


def _norm_hex(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    try:
        return f"0x{int(v, 16):x}"
    except ValueError:
        return v.lower()


def parse_mmi_state(path: Path) -> MmiStateReport:
    try:
        data = path.read_bytes()
    except OSError as e:
        return MmiStateReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _normalize(data)
    report = MmiStateReport(ok=False)

    # 优先从 s_handle_list 起切到结尾附近其它段
    marker = text.find("s_handle_list")
    if marker < 0:
        report.warnings.append("no s_handle_list / MMI handle tree found in .ass")
        return report

    end_markers = [
        "BT:state=",
        "Mutex Information:",
        "ALL created Threads",
        "timer infomation",
        "Print Version",
    ]
    end = len(text)
    for em in end_markers:
        j = text.find(em, marker + 20)
        if j >= 0:
            end = min(end, j)
    section = text[marker:end]

    # handle_list 到 s_zorder 之前
    z_at = section.find("s_zorder_system")
    handle_part = section if z_at < 0 else section[:z_at]
    z_part = ""
    layer_part = ""
    if z_at >= 0:
        rest = section[z_at:]
        l_at = rest.find("s_layer_arr")
        if l_at >= 0:
            z_part = rest[:l_at]
            layer_part = rest[l_at:]
        else:
            z_part = rest

    for m in _NODE_RE.finditer(handle_part):
        node = MmiNode(
            node_type=m.group(2).upper(),
            addr=_norm_hex(m.group(3)),
            handle=_norm_hex(m.group(4)),
            parent_tree_handle=_norm_hex(m.group(5)),
            parent_handle=_norm_hex(m.group(6)),
            id=_norm_hex(m.group(7)),
            name=m.group(8),
            source="handle_list",
        )
        if node.node_type == "APPLET":
            report.applets.append(node)
        elif node.node_type == "WINDOW":
            report.windows.append(node)
        else:
            report.controls.append(node)

    for m in _NODE_RE.finditer(z_part):
        report.zorder.append(
            MmiNode(
                node_type=m.group(2).upper(),
                addr=_norm_hex(m.group(3)),
                handle=_norm_hex(m.group(4)),
                parent_tree_handle=_norm_hex(m.group(5)),
                parent_handle=_norm_hex(m.group(6)),
                id=_norm_hex(m.group(7)),
                name=m.group(8),
                source="zorder",
            )
        )

    for m in _LAYER_RE.finditer(layer_part or section):
        layer = MmiLayer(
            block_id=int(m.group(1)),
            is_bltlayer=int(m.group(2)),
            size=int(m.group(3)),
            name=m.group(4),
            line=int(m.group(5)),
        )
        im = _IMAGE_RE.search(layer_part[m.end() : m.end() + 200] if layer_part else "")
        if im:
            layer.image_info = im.group(1).strip()
        report.layers.append(layer)

    if report.applets:
        report.current_applet = report.applets[0].to_dict()
    # zorder 顶部视为焦点/最前窗体
    if report.zorder:
        top = next((n for n in report.zorder if n.node_type == "WINDOW"), report.zorder[0])
        report.focus_window = top.to_dict()
    elif report.windows:
        report.focus_window = report.windows[0].to_dict()

    for c in report.controls:
        n = (c.name or "").upper()
        if "ANIM" in n or "GIF" in n:
            report.anim_controls.append(c.to_dict())

    report.overall = {
        "applet_count": len(report.applets),
        "window_count": len(report.windows),
        "control_count": len(report.controls),
        "zorder_count": len(report.zorder),
        "layer_count": len(report.layers),
        "anim_control_count": len(report.anim_controls),
        "current_applet_name": (report.current_applet or {}).get("name"),
        "focus_window_name": (report.focus_window or {}).get("name"),
        "focus_window_id": (report.focus_window or {}).get("id"),
    }
    report.ok = bool(
        report.applets or report.windows or report.controls or report.layers
    )
    if not report.ok:
        report.warnings.append("s_handle_list present but no MMI nodes parsed")
    return report


def render_mmi_state_txt(report: MmiStateReport) -> str:
    lines = [
        f"# mmi_state ok={report.ok}",
        f"# overall={report.overall}",
    ]
    for w in report.warnings:
        lines.append(f"# warn: {w}")
    lines += ["", "## current_applet"]
    if report.current_applet:
        a = report.current_applet
        lines.append(
            f"- {a.get('name')} id={a.get('id')} handle={a.get('handle')}"
        )
    else:
        lines.append("(none)")
    lines += ["", "## focus_window"]
    if report.focus_window:
        f = report.focus_window
        lines.append(
            f"- {f.get('name')} id={f.get('id')} handle={f.get('handle')} "
            f"source={f.get('source')}"
        )
    else:
        lines.append("(none)")
    lines += ["", "## anim_controls"]
    if not report.anim_controls:
        lines.append("(none)")
    for c in report.anim_controls:
        lines.append(
            f"- {c.get('name')} id={c.get('id')} handle={c.get('handle')} "
            f"parent={c.get('parent_handle')}"
        )
    lines += ["", "## handle_list"]
    for n in report.applets + report.windows + report.controls:
        lines.append(
            f"- [{n.node_type}] {n.name} id={n.id} handle={n.handle} "
            f"parent={n.parent_handle}"
        )
    lines += ["", "## zorder"]
    if not report.zorder:
        lines.append("(none)")
    for n in report.zorder:
        lines.append(f"- [{n.node_type}] {n.name} id={n.id} handle={n.handle}")
    lines += ["", "## layers"]
    if not report.layers:
        lines.append("(none)")
    for ly in report.layers:
        lines.append(
            f"- block={ly.block_id} blt={ly.is_bltlayer} size={ly.size} "
            f"{ly.name}:{ly.line} {ly.image_info or ''}"
        )
    return "\n".join(lines) + "\n"
