# -*- coding: utf-8 -*-
"""分析流水线。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from dumptrace.ass_parser import addresses_for_symbolize, parse_ass
from dumptrace.callbacks import (
    callback_addrs_for_symbolize,
    enrich_callbacks_symbols,
    parse_callbacks,
)
from dumptrace.callstack import (
    build_callstack_candidates,
    parse_code_ranges,
)
from dumptrace.config import DumpTraceConfig
from dumptrace.credibility import Credibility, assess_credibility
from dumptrace.export_scene import ExportOptions, export_scene
from dumptrace.ingest import ingest, parse_log_stat, refine_symbol_match
from dumptrace.log_meta import parse_log_meta
from dumptrace.mem_stack import extract_stack
from dumptrace.mem_usage import parse_mem_usage
from dumptrace.mem_window import extract_mem_windows
from dumptrace.mmi_state import parse_mmi_state
from dumptrace.ps_info import parse_ps_info
from dumptrace.rtos_info import parse_rtos_info
from dumptrace.rules import apply_rules, overall_confidence
from dumptrace.sideband import parse_sideband
from dumptrace.symbolizer import SymbolInfo, symbolize_addresses
from dumptrace.sync_objects import parse_sync_objects
from dumptrace.timeline import build_timeline


@dataclass
class AnalyzeResult:
    ok: bool
    exit_code: int
    package: Any = None
    scene: Any = None
    symbols: List[SymbolInfo] = field(default_factory=list)
    rules: List = field(default_factory=list)
    credibility: Optional[Credibility] = None
    confidence: str = "low"
    timeline: Any = None
    stack: Any = None
    callstack: Any = None
    symbol_match: Any = None
    mem_usage: Any = None
    rtos_info: Any = None
    sync_objects: Any = None
    mmi_state: Any = None
    callbacks: Any = None
    ps_info: Any = None
    log_meta: Any = None
    mem_window: Any = None
    sideband: Any = None
    warnings: List[str] = field(default_factory=list)
    export: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def analyze(
    input_path: Path,
    *,
    axf: Optional[Path] = None,
    out_dir: Optional[Path] = None,
    addr2line: Optional[Path] = None,
    export: bool = True,
    copy_ass: bool = False,
    bundle: bool = False,
    full: bool = False,
    strict_symbols: bool = False,
    skip_timeline: bool = False,
    skip_mem: bool = False,
    config: Optional[DumpTraceConfig] = None,
) -> AnalyzeResult:
    cfg = (config or DumpTraceConfig()).merged_with_cli(
        addr2line=addr2line,
        copy_ass=copy_ass,
        bundle=bundle,
        full=full,
        strict_symbols=strict_symbols,
        skip_timeline=skip_timeline,
        skip_mem=skip_mem,
    )

    warnings: List[str] = []
    try:
        package = ingest(input_path, axf=axf)
    except FileNotFoundError as e:
        return AnalyzeResult(ok=False, exit_code=1, error=str(e), warnings=warnings)

    try:
        scene = parse_ass(package.ass_path)  # type: ignore[arg-type]
    except OSError as e:
        return AnalyzeResult(
            ok=False, exit_code=1, package=package, error=f"read ass failed: {e}"
        )

    refine_symbol_match(
        package,
        project_version=scene.project_version,
        build_time=scene.build_time,
    )
    warnings.extend(package.warnings)

    mem_usage = None
    if package.ass_path:
        mem_usage = parse_mem_usage(package.ass_path, assert_msg=scene.assert_msg)
        for w in mem_usage.warnings:
            if w not in warnings:
                warnings.append(f"mem_usage: {w}")

    rtos_info = None
    if package.ass_path:
        rtos_info = parse_rtos_info(
            package.ass_path,
            assert_thread_name=scene.thread_name,
            assert_thread_id=scene.thread_id,
            timer_modules=cfg.timer_modules,
            queue_pressure_pct=cfg.queue_pressure_pct,
            stack_overflow_pct=cfg.stack_overflow_pct,
        )
        for w in rtos_info.warnings:
            msg = f"rtos: {w}"
            if msg not in warnings:
                warnings.append(msg)

    sync_objects = None
    mmi_state = None
    callbacks = None
    ps_info = None
    if package.ass_path:
        sync_objects = parse_sync_objects(package.ass_path)
        for w in sync_objects.warnings:
            msg = f"sync: {w}"
            if msg not in warnings:
                warnings.append(msg)
        mmi_state = parse_mmi_state(package.ass_path)
        for w in mmi_state.warnings:
            msg = f"mmi: {w}"
            if msg not in warnings:
                warnings.append(msg)
        callbacks = parse_callbacks(
            package.ass_path,
            assert_addrs=addresses_for_symbolize(scene),
        )
        for w in callbacks.warnings:
            msg = f"callbacks: {w}"
            if msg not in warnings:
                warnings.append(msg)
        ps_info = parse_ps_info(
            package.ass_path, queue_pressure_pct=cfg.queue_pressure_pct
        )
        for w in ps_info.warnings:
            msg = f"ps: {w}"
            if msg not in warnings:
                warnings.append(msg)

    log_meta = None
    if package.ass_path:
        lst_ent = package.get("lst")
        log_meta = parse_log_meta(
            ass_path=package.ass_path,
            armlog_dir=package.armlog_dir,
            package_files=package.files,
            lst_path=lst_ent.path if lst_ent else None,
        )
        for w in log_meta.warnings:
            msg = f"log_meta: {w}"
            if msg not in warnings:
                warnings.append(msg)

    sideband = None
    if cfg.enable_sideband and package.ass_path:
        sideband = parse_sideband(package.ass_path)
        for w in sideband.warnings:
            msg = f"sideband: {w}"
            if msg not in warnings:
                warnings.append(msg)

    log_stat = None
    st = package.get("log_stat")
    if st:
        log_stat = parse_log_stat(st.path)

    credibility = assess_credibility(
        log_stat,
        warn_lost_pct=cfg.warn_lost_pct,
        bad_lost_pct=cfg.bad_lost_pct,
    )
    if credibility.level in ("low", "medium"):
        warnings.append(f"log credibility={credibility.level}: {credibility.message}")
    elif credibility.level == "unknown":
        warnings.append(credibility.message)

    symbols: List[SymbolInfo] = []
    symbol_failed = False

    if package.axf_path:
        items = list(addresses_for_symbolize(scene))
        if callbacks is not None and callbacks.ok:
            items.extend(callback_addrs_for_symbolize(callbacks, limit=40))
        symbols, sym_warns = symbolize_addresses(
            package.axf_path, items, addr2line=cfg.addr2line
        )
        warnings.extend(sym_warns)
        if callbacks is not None and callbacks.ok:
            enrich_callbacks_symbols(callbacks, symbols)
        if not any(s.ok for s in symbols):
            symbol_failed = True
            warnings.append("symbolize produced no successful results")
    else:
        for role, addr in addresses_for_symbolize(scene):
            symbols.append(SymbolInfo(role=role, addr=addr, ok=False, raw="no axf"))

    timeline = None
    if cfg.enable_timeline:
        timeline = build_timeline(
            package.armlog_dir,
            keywords=cfg.timeline_keywords,
            windows_sec=cfg.timeline_windows_sec,
            timeline_modules=cfg.timeline_modules,
        )
        if not timeline.ok:
            warnings.append(f"timeline: {timeline.error}")
        for w in timeline.warnings:
            msg = f"timeline: {w}"
            if msg not in warnings:
                warnings.append(msg)

    stack = None
    callstack = None
    mem_window = None
    if cfg.enable_mem:
        mem_ent = package.get("mem")
        mem_base = scene.mem_base or cfg.mem_base
        if mem_ent and mem_ent.usable:
            stack = extract_stack(
                mem_ent.path,
                stack_start=scene.stack_start,
                stack_end=scene.stack_end,
                mem_base=mem_base,
            )
            if not stack.ok:
                warnings.append(f"stack: {stack.error}")
            else:
                callstack = build_callstack_candidates(
                    stack.data,
                    stack_start=stack.stack_start,
                    axf=package.axf_path,
                    addr2line=cfg.addr2line,
                    code_ranges=parse_code_ranges(cfg.code_ranges),
                )
                for w in callstack.warnings:
                    warnings.append(f"callstack: {w}")
            mem_window = extract_mem_windows(
                mem_ent.path,
                fault_addr=scene.fault_addr,
                regs=scene.regs,
                mem_base=mem_base,
                window_bytes=cfg.mem_window_bytes,
            )
            for w in mem_window.warnings:
                msg = f"mem_window: {w}"
                if msg not in warnings:
                    warnings.append(msg)
        else:
            warnings.append("stack: no usable .mem")

    rules = apply_rules(
        scene,
        mem_usage=mem_usage,
        rtos_info=rtos_info,
        sync_objects=sync_objects,
        mmi_state=mmi_state,
        callbacks=callbacks,
        ps_info=ps_info,
        timeline=timeline,
        log_meta=log_meta,
        mem_window=mem_window,
        sideband=sideband,
        queue_pressure_pct=cfg.queue_pressure_pct,
        stack_overflow_pct=cfg.stack_overflow_pct,
    )

    if out_dir is None:
        out_dir = Path.cwd() / "out" / f"{package.dump_id}_scene"
    else:
        out_dir = out_dir.expanduser().resolve()
        if not out_dir.name.endswith("_scene"):
            out_dir = out_dir / f"{package.dump_id}_scene"

    export_info = None
    if export:
        export_info = export_scene(
            out_dir,
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
            callbacks=callbacks,
            ps_info=ps_info,
            log_meta=log_meta,
            mem_window=mem_window,
            sideband=sideband,
            warnings=warnings,
            options=ExportOptions(
                copy_ass=cfg.copy_ass, bundle=cfg.bundle, full=cfg.full
            ),
        )

    exit_code = 0
    if symbol_failed and cfg.strict_symbols:
        exit_code = 2

    return AnalyzeResult(
        ok=True,
        exit_code=exit_code,
        package=package,
        scene=scene,
        symbols=symbols,
        rules=rules,
        credibility=credibility,
        confidence=overall_confidence(rules),
        timeline=timeline,
        stack=stack,
        callstack=callstack,
        symbol_match=package.symbol_match,
        mem_usage=mem_usage,
        rtos_info=rtos_info,
        sync_objects=sync_objects,
        mmi_state=mmi_state,
        callbacks=callbacks,
        ps_info=ps_info,
        log_meta=log_meta,
        mem_window=mem_window,
        sideband=sideband,
        warnings=warnings,
        export=export_info,
    )
