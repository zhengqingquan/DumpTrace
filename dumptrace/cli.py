# -*- coding: utf-8 -*-
"""命令行入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from dumptrace import __version__
from dumptrace.batch import run_batch
from dumptrace.config import find_config_near, load_config
from dumptrace.diff import diff_dumps
from dumptrace.pipeline import analyze


def _err(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"[INFO] {msg}")


def _done(msg: str) -> None:
    print(f"[DONE] {msg}")


def _add_common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "input",
        type=Path,
        help="dump_* 目录、*_armlog 目录，或 .ass 文件",
    )
    ap.add_argument("--axf", type=Path, default=None, help="符号文件 .axf（可省略自动查找）")
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="输出目录（默认 out/<dump_id>_scene）",
    )
    ap.add_argument(
        "--config",
        type=Path,
        default=None,
        help="dumptrace.toml 路径（默认 cwd 或输入路径向上查找）",
    )
    ap.add_argument(
        "--addr2line",
        type=Path,
        default=None,
        help="addr2line 可执行文件路径（或设 DUMPTRACE_ADDR2LINE）",
    )
    ap.add_argument("--copy-ass", action="store_true", help="将 .ass 复制到 evidence/")
    ap.add_argument("--bundle", action="store_true", help="额外打成 <dump_id>_scene.zip")
    ap.add_argument(
        "--full",
        action="store_true",
        help="复制 mem/logel 等大文件到 evidence/（体积大）",
    )
    ap.add_argument(
        "--strict-symbols",
        action="store_true",
        help="符号反查失败时以退出码 2 表示",
    )
    ap.add_argument(
        "--skip-timeline",
        action="store_true",
        help="跳过 Logel 时间线",
    )
    ap.add_argument(
        "--skip-mem",
        action="store_true",
        help="跳过 mem 栈切片与候选调用栈",
    )


def _resolve_config(args: argparse.Namespace):
    input_path = getattr(args, "input", None) or getattr(args, "a", None)
    if getattr(args, "config", None):
        return load_config(args.config)
    if input_path is not None:
        near = find_config_near(Path(input_path))
        if near is not None:
            return load_config(near)
    return load_config()


def _run_analyze(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    if cfg.source_path:
        _info(f"config={cfg.source_path}")

    result = analyze(
        args.input,
        axf=args.axf,
        out_dir=args.out,
        addr2line=args.addr2line,
        export=True,
        copy_ass=args.copy_ass,
        bundle=args.bundle,
        full=args.full,
        strict_symbols=args.strict_symbols,
        skip_timeline=args.skip_timeline,
        skip_mem=args.skip_mem,
        config=cfg,
    )
    if not result.ok:
        _err(result.error or "analyze failed")
        return result.exit_code

    for w in result.warnings:
        _warn(w)

    scene = result.scene
    _info(
        f"thread={scene.thread_name} fault={scene.fault_addr} "
        f"pc={scene.regs.get('PC')} exception={scene.exception_addr}"
    )
    if result.credibility:
        _info(
            f"log_credibility={result.credibility.level} "
            f"lost={result.credibility.total_lost_pct}"
        )
    if result.timeline and result.timeline.ok:
        n = {k: len(v) for k, v in result.timeline.windows.items()}
        _info(f"timeline source={result.timeline.source} windows={n}")
    if result.stack and result.stack.ok:
        _info(f"stack len={result.stack.length} off={hex(result.stack.file_offset)}")
    if result.callstack and result.callstack.ok:
        ok_n = sum(1 for c in result.callstack.candidates if c.get("ok"))
        _info(f"callstack candidates={len(result.callstack.candidates)} symbolized={ok_n}")

    for s in result.symbols:
        if s.ok:
            _info(f"symbol[{s.role}] {s.addr} -> {s.summary}")
        else:
            _warn(f"symbol[{s.role}] {s.addr} unresolved")

    if result.export:
        _done(f"scene => {result.export['out_dir']}")
        if result.export.get("bundle"):
            _done(f"bundle => {result.export['bundle']}")

    return result.exit_code


def _run_batch(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    if cfg.source_path:
        _info(f"config={cfg.source_path}")

    try:
        summary = run_batch(
            args.input,
            out_dir=args.out,
            axf=args.axf,
            config=cfg,
            copy_ass=args.copy_ass,
            bundle=args.bundle,
            full=args.full,
            strict_symbols=args.strict_symbols,
            addr2line=args.addr2line,
        )
    except FileNotFoundError as e:
        _err(str(e))
        return 1

    for it in summary["items"]:
        row = it.row
        if row.get("ok"):
            _info(
                f"{row['dump_id']}: thread={row['thread']} fault={row['fault_addr']} "
                f"cred={row['log_credibility']} sym={row['exception_symbol']}"
            )
        else:
            _err(f"{row['dump_id']}: {row.get('error')}")

    _done(f"batch {summary['ok']}/{summary['total']} ok => {summary['summary_csv']}")
    return 0 if summary["failed"] == 0 else 1


def _run_diff(args: argparse.Namespace) -> int:
    out = args.out
    if out is None:
        out = Path.cwd() / "out" / "diff.json"
    elif out.is_dir() or str(out).endswith(("\\", "/")):
        out = Path(out) / "diff.json"

    try:
        diff = diff_dumps(
            args.a,
            args.b,
            out_path=out,
            axf=args.axf,
            addr2line=args.addr2line,
            skip_timeline=True,
            skip_mem=True,
        )
    except Exception as e:
        _err(f"{type(e).__name__}: {e}")
        return 1

    _info(f"identical={diff.get('identical')} changes={len(diff.get('changes') or [])}")
    for c in diff.get("changes") or []:
        _info(f"  {c['field']}: {c['a']} -> {c['b']}")
    _done(f"diff => {diff.get('out_md')}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dumptrace",
        description="Analyze Unisoc/UIS armlog crash dumps and export crash scenes",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"dumptrace {__version__}",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_an = sub.add_parser("analyze", help="分析死机包并导出现场")
    _add_common(p_an)

    p_ex = sub.add_parser("export-scene", help="导出现场包（与 analyze 相同）")
    _add_common(p_ex)

    p_batch = sub.add_parser("batch", help="批量分析父目录下多个 dump，写出 summary.csv")
    _add_common(p_batch)

    p_diff = sub.add_parser("diff", help="对比两个 dump / scene.json")
    p_diff.add_argument("a", type=Path, help="dump A 或 scene 目录/scene.json")
    p_diff.add_argument("b", type=Path, help="dump B 或 scene 目录/scene.json")
    p_diff.add_argument("--axf", type=Path, default=None)
    p_diff.add_argument("--addr2line", type=Path, default=None)
    p_diff.add_argument("--out", type=Path, default=None, help="diff.json 输出路径")
    p_diff.add_argument("--config", type=Path, default=None)

    p_ver = sub.add_parser("version", help="显示版本")

    args = parser.parse_args(argv)
    if args.cmd in (None,):
        parser.print_help()
        return 1
    if args.cmd == "version":
        print(f"dumptrace {__version__}")
        return 0
    if args.cmd in ("analyze", "export-scene"):
        return _run_analyze(args)
    if args.cmd == "batch":
        return _run_batch(args)
    if args.cmd == "diff":
        return _run_diff(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
