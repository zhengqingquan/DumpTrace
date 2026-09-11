# -*- coding: utf-8 -*-
"""双 dump / 双现场差异对比。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dumptrace.pipeline import AnalyzeResult, analyze


_COMPARE_KEYS = (
    "thread_name",
    "fault_addr",
    "exception_addr",
    "assert_msg",
    "pc",
    "project_version",
    "exception_symbol",
    "rule_ids",
    "confidence",
    "log_credibility",
)


def _scene_summary_from_result(result: AnalyzeResult) -> Dict[str, Any]:
    if not result.ok or result.scene is None:
        return {
            "ok": False,
            "error": result.error or "analyze failed",
        }
    scene = result.scene
    exc_sym = ""
    for s in result.symbols:
        if s.role == "exception" and s.ok:
            exc_sym = s.func or ""
            break
    return {
        "ok": True,
        "dump_id": result.package.dump_id if result.package else "",
        "thread_name": scene.thread_name,
        "fault_addr": scene.fault_addr,
        "exception_addr": scene.exception_addr,
        "assert_msg": scene.assert_msg,
        "pc": (scene.regs or {}).get("PC"),
        "project_version": scene.project_version,
        "exception_symbol": exc_sym,
        "rule_ids": [r.id for r in result.rules],
        "confidence": result.confidence,
        "log_credibility": result.credibility.level if result.credibility else None,
        "scene_dir": (result.export or {}).get("out_dir"),
    }


def _scene_summary_from_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    a = data.get("assert") or {}
    regs = a.get("regs") or {}
    exc_sym = ""
    for s in data.get("symbols") or []:
        if s.get("role") == "exception" and s.get("ok"):
            exc_sym = s.get("func") or ""
            break
    return {
        "ok": True,
        "dump_id": data.get("dump_id"),
        "thread_name": a.get("thread_name"),
        "fault_addr": a.get("fault_addr"),
        "exception_addr": a.get("exception_addr"),
        "assert_msg": a.get("assert_msg"),
        "pc": regs.get("PC"),
        "project_version": a.get("project_version"),
        "exception_symbol": exc_sym,
        "rule_ids": [r.get("id") for r in (data.get("rules") or [])],
        "confidence": data.get("confidence"),
        "log_credibility": (data.get("credibility") or {}).get("level"),
        "scene_dir": str(path.parent),
    }


def load_summary(path: Path, **analyze_kw: Any) -> Dict[str, Any]:
    """path 可以是 dump 目录、armlog、或 scene.json。"""
    path = path.expanduser().resolve()
    if path.is_file() and path.name == "scene.json":
        return _scene_summary_from_json(path)
    if path.is_dir() and (path / "scene.json").is_file():
        return _scene_summary_from_json(path / "scene.json")
    result = analyze(path, export=False, **analyze_kw)
    return _scene_summary_from_result(result)


def diff_summaries(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    changes: List[Dict[str, Any]] = []
    same: List[str] = []
    for key in _COMPARE_KEYS:
        va = a.get(key)
        vb = b.get(key)
        if va != vb:
            changes.append({"field": key, "a": va, "b": vb})
        else:
            same.append(key)
    return {
        "a": {k: a.get(k) for k in ("dump_id", "scene_dir", "ok", "error")},
        "b": {k: b.get(k) for k in ("dump_id", "scene_dir", "ok", "error")},
        "same": same,
        "changes": changes,
        "identical": len(changes) == 0 and a.get("ok") and b.get("ok"),
    }


def render_diff_md(diff: Dict[str, Any]) -> str:
    lines = [
        "# DumpTrace diff",
        "",
        f"- A: `{diff['a'].get('dump_id')}` ({diff['a'].get('scene_dir')})",
        f"- B: `{diff['b'].get('dump_id')}` ({diff['b'].get('scene_dir')})",
        f"- identical: **{diff.get('identical')}**",
        "",
        "## Changes",
        "",
    ]
    if not diff.get("changes"):
        lines.append("- （无差异字段）")
    else:
        for c in diff["changes"]:
            lines.append(f"- **{c['field']}**: `{c['a']}` → `{c['b']}`")
    lines += ["", "## Same", "", ", ".join(diff.get("same") or []) or "（无）", ""]
    return "\n".join(lines)


def diff_dumps(
    path_a: Path,
    path_b: Path,
    *,
    out_path: Optional[Path] = None,
    **analyze_kw: Any,
) -> Dict[str, Any]:
    sa = load_summary(path_a, **analyze_kw)
    sb = load_summary(path_b, **analyze_kw)
    diff = diff_summaries(sa, sb)
    if out_path is not None:
        out_path = out_path.expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(diff, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        md = out_path.with_suffix(".md")
        md.write_text(render_diff_md(diff), encoding="utf-8")
        diff["out_json"] = str(out_path)
        diff["out_md"] = str(md)
    return diff
