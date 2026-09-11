# -*- coding: utf-8 -*-
"""批量分析多个 dump。"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from dumptrace.config import DumpTraceConfig
from dumptrace.pipeline import AnalyzeResult, analyze


@dataclass
class BatchItem:
    input_path: Path
    result: AnalyzeResult
    row: Dict[str, Any] = field(default_factory=dict)


def discover_dump_inputs(root: Path) -> List[Path]:
    """
    在父目录下发现可分析输入：
      - 直接子目录名 dump_* 或 *_armlog
      - 或含 .ass 的子目录
    去重：同一 armlog 只保留一层。
    """
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"batch root not found: {root}")

    found: List[Path] = []
    seen_armlog = set()

    def add_armlog(p: Path) -> None:
        key = str(p.resolve())
        if key in seen_armlog:
            return
        seen_armlog.add(key)
        found.append(p.resolve())

    # 优先 dump_* 目录
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        if name.startswith("dump_") or name.endswith("_armlog"):
            add_armlog(child)
            continue
        # 子层 *_armlog
        nested = list(child.glob("*_armlog"))
        if nested:
            add_armlog(child)
            continue
        if list(child.glob("*.ass")) or list(child.rglob("*.ass")):
            add_armlog(child)

    # 根目录本身就是 armlog
    if root.name.endswith("_armlog") or list(root.glob("*.ass")):
        if not found:
            add_armlog(root)

    return found


def _summary_row(input_path: Path, result: AnalyzeResult) -> Dict[str, Any]:
    if not result.ok or result.scene is None:
        return {
            "dump_id": input_path.name,
            "input": str(input_path),
            "ok": False,
            "exit_code": result.exit_code,
            "error": result.error or "",
            "thread": "",
            "fault_addr": "",
            "exception": "",
            "pc": "",
            "assert_msg": "",
            "project": "",
            "rule_ids": "",
            "confidence": "",
            "log_credibility": "",
            "log_lost_pct": "",
            "symbol_ok": "",
            "exception_symbol": "",
            "scene_dir": "",
        }

    scene = result.scene
    package = result.package
    dump_id = package.dump_id if package else input_path.name
    rules = ",".join(r.id for r in (result.rules or []))
    sym_ok = sum(1 for s in result.symbols if s.ok)
    exc_sym = ""
    for s in result.symbols:
        if s.role == "exception" and s.ok:
            exc_sym = s.func or ""
            break
    cred = result.credibility
    return {
        "dump_id": dump_id,
        "input": str(input_path),
        "ok": True,
        "exit_code": result.exit_code,
        "error": "",
        "thread": scene.thread_name or "",
        "fault_addr": scene.fault_addr or "",
        "exception": scene.exception_addr or "",
        "pc": (scene.regs or {}).get("PC", ""),
        "assert_msg": scene.assert_msg or "",
        "project": scene.project_version or "",
        "rule_ids": rules,
        "confidence": result.confidence or "",
        "log_credibility": cred.level if cred else "",
        "log_lost_pct": (
            ""
            if not cred or cred.total_lost_pct is None
            else f"{cred.total_lost_pct:.2f}"
        ),
        "symbol_ok": sym_ok,
        "exception_symbol": exc_sym,
        "scene_dir": (result.export or {}).get("out_dir", ""),
    }


def run_batch(
    root: Path,
    *,
    out_dir: Optional[Path] = None,
    axf: Optional[Path] = None,
    config: Optional[DumpTraceConfig] = None,
    copy_ass: bool = False,
    bundle: bool = False,
    full: bool = False,
    strict_symbols: bool = False,
    addr2line: Optional[Path] = None,
    inputs: Optional[Sequence[Path]] = None,
) -> Dict[str, Any]:
    cfg = config or DumpTraceConfig()
    cfg = cfg.merged_with_cli(
        addr2line=addr2line,
        copy_ass=copy_ass,
        bundle=bundle,
        full=full,
        strict_symbols=strict_symbols,
    )

    dump_inputs = list(inputs) if inputs is not None else discover_dump_inputs(root)
    if out_dir is None:
        out_dir = Path.cwd() / "out" / "batch"
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    items: List[BatchItem] = []
    for inp in dump_inputs:
        result = analyze(
            inp,
            axf=axf,
            out_dir=out_dir,
            addr2line=cfg.addr2line,
            export=True,
            copy_ass=cfg.copy_ass,
            bundle=cfg.bundle,
            full=cfg.full,
            strict_symbols=cfg.strict_symbols,
            config=cfg,
        )
        row = _summary_row(inp, result)
        items.append(BatchItem(input_path=inp, result=result, row=row))

    csv_path = out_dir / "summary.csv"
    fieldnames = list(items[0].row.keys()) if items else [
        "dump_id",
        "input",
        "ok",
        "exit_code",
        "error",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for it in items:
            writer.writerow(it.row)

    ok_n = sum(1 for it in items if it.result.ok)
    return {
        "out_dir": str(out_dir),
        "summary_csv": str(csv_path),
        "total": len(items),
        "ok": ok_n,
        "failed": len(items) - ok_n,
        "items": items,
    }
