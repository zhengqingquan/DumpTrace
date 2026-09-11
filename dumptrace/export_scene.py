# -*- coding: utf-8 -*-
"""导出死机现场包。"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dumptrace import __version__
from dumptrace.ass_parser import AssertScene
from dumptrace.credibility import Credibility
from dumptrace.ingest import PackageInfo
from dumptrace.rules import RuleHit, overall_confidence
from dumptrace.symbolizer import SymbolInfo


@dataclass
class ExportOptions:
    copy_ass: bool = False
    bundle: bool = False
    full: bool = False


def _file_sha256(path: Path, limit: int = 1024 * 1024) -> str:
    """大文件只哈希前 1MB + 大小，避免扫 70MB+ mem。"""
    h = hashlib.sha256()
    size = path.stat().st_size
    h.update(f"size:{size}|".encode())
    with path.open("rb") as f:
        h.update(f.read(limit))
    return h.hexdigest()


def build_scene_dict(
    *,
    package: PackageInfo,
    scene: AssertScene,
    symbols: List[SymbolInfo],
    rules: List[RuleHit],
    log_stat: Optional[Dict[str, str]],
    credibility: Optional[Credibility],
    warnings: List[str],
    timeline: Any = None,
    stack: Any = None,
    callstack: Any = None,
    mem_usage: Any = None,
    rtos_info: Any = None,
    sync_objects: Any = None,
    mmi_state: Any = None,
) -> Dict[str, Any]:
    return {
        "tool": {"name": "dumptrace", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dump_id": package.dump_id,
        "package": package.to_dict(),
        "assert": scene.to_dict(),
        "symbols": [s.to_dict() for s in symbols],
        "rules": [r.to_dict() for r in rules],
        "confidence": overall_confidence(rules),
        "log_stat": log_stat,
        "credibility": credibility.to_dict() if credibility else None,
        "timeline": timeline.to_dict() if timeline is not None else None,
        "stack": stack.to_dict() if stack is not None else None,
        "callstack": callstack.to_dict() if callstack is not None else None,
        "mem_usage": mem_usage.to_dict() if mem_usage is not None and hasattr(mem_usage, "to_dict") else mem_usage,
        "rtos_info": (
            rtos_info.to_dict()
            if rtos_info is not None and hasattr(rtos_info, "to_dict")
            else rtos_info
        ),
        "sync_objects": (
            sync_objects.to_dict()
            if sync_objects is not None and hasattr(sync_objects, "to_dict")
            else sync_objects
        ),
        "mmi_state": (
            mmi_state.to_dict()
            if mmi_state is not None and hasattr(mmi_state, "to_dict")
            else mmi_state
        ),
        "warnings": warnings,
    }


def render_scene_md(data: Dict[str, Any]) -> str:
    a = data.get("assert") or {}
    regs = a.get("regs") or {}
    lines = [
        f"# DumpTrace 死机现场 — {data.get('dump_id', '')}",
        "",
        "## 结论摘要",
        "",
    ]
    rules = data.get("rules") or []
    if rules:
        for r in rules:
            lines.append(f"- **{r.get('id')}** ({r.get('confidence')}): {r.get('message')}")
    else:
        lines.append("- （无规则命中）")
    lines += [
        "",
        f"- 综合置信度: **{data.get('confidence', 'low')}**",
        "",
        "## 抓 log 可信度",
        "",
    ]
    cred = data.get("credibility") or {}
    if cred:
        lines += [
            f"- 等级: **{cred.get('level', 'unknown')}**",
            f"- Total lost: `{cred.get('total_lost_pct')}`%",
            f"- PS MTA lost: `{cred.get('ps_mta_lost_pct')}`%",
            f"- lost_count: `{cred.get('total_lost_count')}` / packages `{cred.get('total_package')}`",
            f"- 说明: {cred.get('message', '')}",
        ]
    else:
        lines.append("- （无评估）")

    lines += [
        "",
        "## 异常画像",
        "",
        f"- Assert: `{a.get('assert_msg')}`",
        f"- Exception: `{a.get('exception_addr')}`",
        f"- Fault: `{a.get('fault_desc')}`",
        f"- Fault address: `{a.get('fault_addr')}`",
        f"- Thread: `{a.get('thread_name')}` (id={a.get('thread_id')}, queue={a.get('queue_name')})",
        f"- Project: `{a.get('project_version')}`",
        f"- Platform: `{a.get('platform_version')}`",
        f"- Build time: `{a.get('build_time')}`",
        "",
        "## 内存使用",
        "",
    ]
    mu = data.get("mem_usage") or {}
    if mu.get("ok"):
        ov = mu.get("overall") or {}
        lines.append(
            f"- overall: used=`{ov.get('used')}` / total=`{ov.get('total')}` "
            f"avail=`{ov.get('avail')}` used_pct=`{ov.get('used_pct')}`% "
            f"(source=`{ov.get('source')}`)"
        )
        for p in mu.get("pools") or []:
            kind = p.get("kind") or "main"
            lines.append(
                f"- pool **{p.get('name')}** [{kind}]: total=`{p.get('total')}` "
                f"used=`{p.get('used')}` avail=`{p.get('avail')}` "
                f"max_used=`{p.get('max_used')}` used_pct=`{p.get('used_pct')}`%"
            )
        segs = mu.get("segments") or []
        if segs:
            lines.append(f"- segments: {len(segs)}（详见 mem_usage.txt）")
            # 按空闲少/使用多挑几条
            pressured = sorted(
                segs,
                key=lambda s: (s.get("free_bytes") or 0, -(s.get("alloc_bytes") or 0)),
            )[:5]
            for s in pressured:
                lines.append(
                    f"  - [{s.get('space')}] {s.get('title')}: "
                    f"alloc=`{s.get('alloc_bytes')}` free=`{s.get('free_bytes')}` "
                    f"largest_free=`{s.get('largest_free')}`"
                )
        ai = mu.get("allocated_info") or {}
        if ai.get("top_files"):
            lines.append(
                f"- Allocated memory info: count=`{ai.get('count')}` "
                f"total_bytes=`{ai.get('total_bytes')}`；占用 Top："
            )
            for f in (ai.get("top_files") or [])[:8]:
                lines.append(
                    f"  - `{f.get('file')}`: bytes=`{f.get('bytes')}` blocks=`{f.get('blocks')}`"
                )
        if mu.get("largest_free_blocks"):
            lines.append("- 最大空闲块：")
            for b in (mu.get("largest_free_blocks") or [])[:5]:
                lines.append(
                    f"  - size=`{b.get('size')}` `{b.get('start')}`-`{b.get('end')}`"
                )
    elif mu:
        warn = mu.get("warnings") or "n/a"
        lines.append(f"- 未解析到完整表: {warn}")
    else:
        lines.append("- （无）")

    lines += [
        "",
        "## 任务 / 队列 / 定时器",
        "",
    ]
    ri = data.get("rtos_info") or {}
    if ri.get("ok"):
        ov = ri.get("overall") or {}
        lines.append(
            f"- tasks=`{ov.get('task_count')}` timers=`{ov.get('timer_count')}` "
            f"(periodic=`{ov.get('periodic_timer_count')}`) "
            f"queues=`{ov.get('queue_count')}` pressured=`{ov.get('pressured_queue_count')}` "
            f"current=`{ov.get('current_task')}`"
        )
        sus = ri.get("suspicious_tasks") or []
        if sus:
            lines.append("- 可疑线程：")
            for s in sus[:8]:
                lines.append(
                    f"  - `{s.get('name')}` ({s.get('task_id')}): "
                    f"{', '.join(s.get('reasons') or [])}"
                )
        else:
            lines.append("- 可疑线程：（无）")
        mods = ri.get("timer_module_counts") or {}
        if mods:
            top_mods = ", ".join(
                f"{k}={v}" for k, v in sorted(mods.items(), key=lambda kv: -kv[1])[:8]
            )
            lines.append(f"- 定时器模块分布: {top_mods}")
        lines.append("- 详见 `tasks.txt` / `timers.txt` / `tasks.json`")
    elif ri:
        warn = ri.get("warnings") or "n/a"
        lines.append(f"- 未解析到完整表: {warn}")
    else:
        lines.append("- （无）")

    lines += [
        "",
        "## 同步原语",
        "",
    ]
    so = data.get("sync_objects") or {}
    if so.get("ok"):
        ov = so.get("overall") or {}
        lines.append(
            f"- mutex=`{ov.get('mutex_count')}` sem=`{ov.get('semaphore_count')}` "
            f"event=`{ov.get('event_count')}` held=`{ov.get('held_count')}` "
            f"waited=`{ov.get('waited_count')}`"
        )
        held = so.get("held_locks") or []
        if held:
            lines.append("- 持有中的锁：")
            for h in held[:8]:
                lines.append(
                    f"  - `{h.get('name')}` owner=`{h.get('owner')}` "
                    f"count=`{h.get('ownership_count')}`"
                )
        waited = so.get("waited") or []
        if waited:
            lines.append("- 有等待者：")
            for w in waited[:8]:
                lines.append(
                    f"  - [{w.get('kind')}] `{w.get('name')}` "
                    f"suspended=`{w.get('total_suspended')}` "
                    f"waiters=`{w.get('waiters')}`"
                )
        lines.append("- 详见 `sync_objects.txt` / `sync_objects.json`")
    elif so:
        lines.append(f"- 未解析到完整表: {so.get('warnings') or 'n/a'}")
    else:
        lines.append("- （无）")

    lines += [
        "",
        "## MMI / UI 状态",
        "",
    ]
    mi = data.get("mmi_state") or {}
    if mi.get("ok"):
        ov = mi.get("overall") or {}
        lines.append(
            f"- applet=`{ov.get('current_applet_name')}` "
            f"focus=`{ov.get('focus_window_name')}` "
            f"(id=`{ov.get('focus_window_id')}`) "
            f"windows=`{ov.get('window_count')}` controls=`{ov.get('control_count')}` "
            f"anim=`{ov.get('anim_control_count')}`"
        )
        for c in (mi.get("anim_controls") or [])[:5]:
            lines.append(
                f"  - anim `{c.get('name')}` id=`{c.get('id')}` handle=`{c.get('handle')}`"
            )
        lines.append("- 详见 `mmi_state.txt` / 写入 scene.json 的 `mmi_state`")
    elif mi:
        lines.append(f"- 未解析到: {mi.get('warnings') or 'n/a'}")
    else:
        lines.append("- （无）")

    lines += [
        "",
        "## 关键寄存器",
        "",
        f"- PC=`{regs.get('PC')}` LR=`{regs.get('LR') or regs.get('R14')}` R0=`{regs.get('R0')}`",
        "",
        "## 符号定位",
        "",
    ]
    for s in data.get("symbols") or []:
        if s.get("ok"):
            loc = s.get("file") or ""
            if s.get("line"):
                loc = f"{loc}:{s['line']}"
            lines.append(
                f"- **{s.get('role')}** `{s.get('addr')}` → `{s.get('func')}` @ `{loc}`"
            )
        else:
            lines.append(f"- **{s.get('role')}** `{s.get('addr')}` → （未解析）")

    # 时间线 / 栈摘要
    tl = data.get("timeline") or {}
    lines += ["", "## 死机前时间线", ""]
    if tl.get("ok"):
        lines.append(f"- source: `{tl.get('source')}` lines={tl.get('total_lines')}")
        for win, evs in (tl.get("windows") or {}).items():
            lines.append(f"- window **{win}**: {len(evs)} 条关键字命中（详见 timeline.txt）")
            for e in (evs or [])[-5:]:
                lines.append(f"  - `{e.get('ue_time')}` {e.get('content', '')[:120]}")
    elif tl:
        lines.append(f"- 失败: {tl.get('error')}")
    else:
        lines.append("- （未启用或未生成）")

    st = data.get("stack") or {}
    cs = data.get("callstack") or {}
    lines += ["", "## 栈 / 候选调用栈", ""]
    if st.get("ok"):
        lines.append(
            f"- stack `{hex(st.get('stack_start', 0))}`-`{hex(st.get('stack_end', 0))}` "
            f"len={st.get('length')} → stack.bin / stack.hex"
        )
    elif st:
        lines.append(f"- stack 失败: {st.get('error')}")
    else:
        lines.append("- （未启用或无 mem）")
    if cs.get("ok"):
        ok_n = sum(1 for c in (cs.get("candidates") or []) if c.get("ok"))
        lines.append(f"- callstack candidates: {len(cs.get('candidates') or [])}（符号成功 {ok_n}）")
        for c in (cs.get("candidates") or [])[:8]:
            if not c.get("ok"):
                continue
            loc = c.get("file") or ""
            if c.get("line"):
                loc = f"{loc}:{c['line']}"
            lines.append(f"  - `{c.get('code_addr')}` → `{c.get('func')}` @ `{loc}`")
    elif cs:
        lines.append(f"- callstack: {cs.get('error') or 'n/a'}")

    pkg = data.get("package") or {}
    lines += [
        "",
        "## 符号匹配",
        "",
        f"- overall `axf_match`: `{pkg.get('axf_match')}`",
    ]
    sm = pkg.get("symbol_match") or data.get("symbol_match") or {}
    checks = sm.get("checks") if isinstance(sm, dict) else None
    if checks:
        for c in checks:
            lines.append(
                f"- **{c.get('name')}**: `{c.get('status')}` — {c.get('message')}"
            )
    else:
        lines.append("- （未检查）")

    lines += [
        "",
        "## 源包",
        "",
        f"- root: `{pkg.get('root')}`",
        f"- armlog: `{pkg.get('armlog_dir')}`",
        f"- axf_match: `{pkg.get('axf_match')}`",
        "",
        "## 警告",
        "",
    ]
    warns = data.get("warnings") or []
    if warns:
        for w in warns:
            lines.append(f"- {w}")
    else:
        lines.append("- （无）")

    lines += [
        "",
        f"— generated by dumptrace {data.get('tool', {}).get('version', '')}",
        "",
    ]
    return "\n".join(lines)


def render_symbols_txt(symbols: List[SymbolInfo]) -> str:
    rows = ["role\taddr\tfunc\tfile:line\tok"]
    for s in symbols:
        loc = s.file or ""
        if s.line:
            loc = f"{loc}:{s.line}"
        rows.append(f"{s.role}\t{s.addr}\t{s.func or ''}\t{loc}\t{s.ok}")
    return "\n".join(rows) + "\n"


def build_manifest(package: PackageInfo, out_dir: Path) -> Dict[str, Any]:
    files = []
    for f in package.files:
        item = {
            "role": f.role,
            "path": str(f.path),
            "size": f.size,
            "usable": f.usable,
        }
        if f.path.is_file() and f.size > 0:
            try:
                item["sha256_prefix"] = _file_sha256(f.path)
            except OSError:
                pass
        files.append(item)
    return {
        "dump_id": package.dump_id,
        "exported_to": str(out_dir),
        "tool_version": __version__,
        "files": files,
    }


def export_scene(
    out_dir: Path,
    *,
    package: PackageInfo,
    scene: AssertScene,
    symbols: List[SymbolInfo],
    rules: List[RuleHit],
    log_stat: Optional[Dict[str, str]],
    credibility: Optional[Credibility] = None,
    timeline: Any = None,
    stack: Any = None,
    callstack: Any = None,
    mem_usage: Any = None,
    rtos_info: Any = None,
    sync_objects: Any = None,
    mmi_state: Any = None,
    warnings: List[str],
    options: Optional[ExportOptions] = None,
) -> Dict[str, Any]:
    options = options or ExportOptions()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    data = build_scene_dict(
        package=package,
        scene=scene,
        symbols=symbols,
        rules=rules,
        log_stat=log_stat,
        credibility=credibility,
        timeline=timeline,
        stack=stack,
        callstack=callstack,
        mem_usage=mem_usage,
        rtos_info=rtos_info,
        sync_objects=sync_objects,
        mmi_state=mmi_state,
        warnings=warnings,
    )

    scene_json = out_dir / "scene.json"
    scene_md = out_dir / "scene.md"
    excerpt = out_dir / "assert_excerpt.txt"
    symbols_txt = out_dir / "symbols.txt"
    manifest_path = out_dir / "manifest.json"

    scene_json.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    scene_md.write_text(render_scene_md(data), encoding="utf-8")
    excerpt.write_text(scene.excerpt or "", encoding="utf-8")
    symbols_txt.write_text(render_symbols_txt(symbols), encoding="utf-8")

    extra_files: List[Path] = []
    if timeline is not None:
        from dumptrace.timeline import render_timeline_txt

        tp = out_dir / "timeline.txt"
        tp.write_text(render_timeline_txt(timeline), encoding="utf-8")
        extra_files.append(tp)
    if stack is not None:
        from dumptrace.mem_stack import write_stack_files

        extra_files.extend(write_stack_files(out_dir, stack))
    if callstack is not None:
        from dumptrace.callstack import render_callstack_txt

        cp = out_dir / "callstack_candidates.txt"
        cp.write_text(render_callstack_txt(callstack), encoding="utf-8")
        extra_files.append(cp)
    if mem_usage is not None:
        from dumptrace.mem_usage import render_mem_usage_txt

        mp = out_dir / "mem_usage.txt"
        mp.write_text(render_mem_usage_txt(mem_usage), encoding="utf-8")
        extra_files.append(mp)
        mj = out_dir / "mem_usage.json"
        payload = (
            mem_usage.to_dict()
            if hasattr(mem_usage, "to_dict")
            else mem_usage
        )
        mj.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        extra_files.append(mj)
    if rtos_info is not None:
        from dumptrace.rtos_info import render_tasks_txt, render_timers_txt

        tp = out_dir / "tasks.txt"
        tp.write_text(render_tasks_txt(rtos_info), encoding="utf-8")
        extra_files.append(tp)
        tj = out_dir / "tasks.json"
        payload = (
            rtos_info.to_dict()
            if hasattr(rtos_info, "to_dict")
            else rtos_info
        )
        tj.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        extra_files.append(tj)
        tip = out_dir / "timers.txt"
        tip.write_text(render_timers_txt(rtos_info), encoding="utf-8")
        extra_files.append(tip)
    if sync_objects is not None:
        from dumptrace.sync_objects import render_sync_objects_txt

        sp = out_dir / "sync_objects.txt"
        sp.write_text(render_sync_objects_txt(sync_objects), encoding="utf-8")
        extra_files.append(sp)
        sj = out_dir / "sync_objects.json"
        payload = (
            sync_objects.to_dict()
            if hasattr(sync_objects, "to_dict")
            else sync_objects
        )
        sj.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        extra_files.append(sj)
    if mmi_state is not None:
        from dumptrace.mmi_state import render_mmi_state_txt

        mp = out_dir / "mmi_state.txt"
        mp.write_text(render_mmi_state_txt(mmi_state), encoding="utf-8")
        extra_files.append(mp)

    evidence_dir = out_dir / "evidence"
    if options.copy_ass or options.full:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        if package.ass_path:
            shutil.copy2(package.ass_path, evidence_dir / package.ass_path.name)
        if options.full:
            for role in ("logel", "mem", "log_stat", "lst"):
                ent = package.get(role)
                if ent and ent.usable and ent.path.is_file():
                    shutil.copy2(ent.path, evidence_dir / ent.path.name)

    manifest = build_manifest(package, out_dir)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    result = {
        "out_dir": str(out_dir),
        "files": [
            str(scene_json),
            str(scene_md),
            str(excerpt),
            str(symbols_txt),
            str(manifest_path),
            *[str(p) for p in extra_files],
        ],
        "bundle": None,
    }

    if options.bundle:
        zip_path = out_dir.parent / f"{package.dump_id}_scene.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name in (
                "scene.json",
                "scene.md",
                "assert_excerpt.txt",
                "symbols.txt",
                "manifest.json",
                "timeline.txt",
                "stack.bin",
                "stack.hex",
                "callstack_candidates.txt",
                "mem_usage.txt",
                "mem_usage.json",
                "tasks.txt",
                "tasks.json",
                "timers.txt",
                "sync_objects.txt",
                "sync_objects.json",
                "mmi_state.txt",
            ):
                p = out_dir / name
                if p.is_file():
                    zf.write(p, arcname=f"{package.dump_id}_scene/{name}")
            if evidence_dir.is_dir():
                for p in evidence_dir.iterdir():
                    if p.is_file():
                        zf.write(
                            p,
                            arcname=f"{package.dump_id}_scene/evidence/{p.name}",
                        )
        result["bundle"] = str(zip_path)
        result["files"].append(str(zip_path))

    return result
