# -*- coding: utf-8 -*-
"""基于 log_stat 的抓 log 可信度评估。"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class Credibility:
    level: str  # high / medium / low / unknown
    total_lost_pct: Optional[float] = None
    ps_mta_lost_pct: Optional[float] = None
    total_lost_count: Optional[int] = None
    total_package: Optional[int] = None
    message: str = ""
    raw: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _to_float(v: Optional[str]) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _to_int(v: Optional[str]) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(float(v))
    except ValueError:
        return None


def assess_credibility(
    log_stat: Optional[Dict[str, str]],
    *,
    warn_lost_pct: float = 5.0,
    bad_lost_pct: float = 15.0,
) -> Credibility:
    """
    依据 Total lost / PS MTA lost 百分比评估时间线可信度。
    阈值可通过配置覆盖。
    """
    if not log_stat:
        return Credibility(
            level="unknown",
            message="无 *_log_stat.txt，无法评估抓 log 丢包；后续时间线结论需谨慎",
        )

    total = _to_float(log_stat.get("Total lost"))
    mta = _to_float(log_stat.get("PS MTA lost"))
    count = _to_int(log_stat.get("Total lost count"))
    pkgs = _to_int(log_stat.get("Total package") or log_stat.get("PS Total package"))

    # 取更差的一个作为主指标
    metric = None
    for v in (total, mta):
        if v is None:
            continue
        metric = v if metric is None else max(metric, v)

    if metric is None:
        return Credibility(
            level="unknown",
            total_lost_pct=total,
            ps_mta_lost_pct=mta,
            total_lost_count=count,
            total_package=pkgs,
            message="log_stat 存在但缺少 Total lost / PS MTA lost 字段",
            raw=dict(log_stat),
        )

    if metric >= bad_lost_pct:
        level = "low"
        message = (
            f"抓 log 丢包约 {metric:.2f}%（阈值≥{bad_lost_pct}%），"
            f"时间线可能有明显缺口，业务侧结论需降权"
        )
    elif metric >= warn_lost_pct:
        level = "medium"
        message = (
            f"抓 log 丢包约 {metric:.2f}%（阈值≥{warn_lost_pct}%），"
            f"存在一定缺口，关键事件附近建议对照其它证据"
        )
    else:
        level = "high"
        message = f"抓 log 丢包约 {metric:.2f}%，对异常画像影响较小"

    if count is not None and pkgs is not None:
        message += f"；lost_count={count}/{pkgs} packages"

    return Credibility(
        level=level,
        total_lost_pct=total,
        ps_mta_lost_pct=mta,
        total_lost_count=count,
        total_package=pkgs,
        message=message,
        raw=dict(log_stat),
    )
