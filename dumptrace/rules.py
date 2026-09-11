# -*- coding: utf-8 -*-
"""规则引擎。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from dumptrace.ass_parser import AssertScene


THREAD_HINTS = {
    "T_P_APP": "应用消息线程（常见于 APP/相机/UI 消息处理路径）",
    "T_MMI": "人机界面线程",
    "T_USB": "USB 相关线程",
}


@dataclass
class RuleHit:
    id: str
    confidence: str  # high / medium / low
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def apply_rules(scene: AssertScene) -> List[RuleHit]:
    hits: List[RuleHit] = []

    fault = scene.fault_addr
    if fault:
        try:
            addr = int(fault, 16)
        except ValueError:
            addr = None
        if addr is not None and 0 <= addr <= 0x100 and addr % 4 == 0:
            hits.append(
                RuleHit(
                    id="null_deref",
                    confidence="high",
                    message=f"Fault address {fault} 落在空指针小偏移，疑似 NULL->member 解引用",
                    evidence={"fault_addr": fault, "offset": addr},
                )
            )

    desc = (scene.fault_desc or "") + " " + (scene.assert_msg or "")
    desc_l = desc.lower()
    if "abort" in desc_l or "permission fault" in desc_l or "translation fault" in desc_l:
        hits.append(
            RuleHit(
                id="data_abort",
                confidence="high",
                message="命中 Data Abort / Abort exception 路径",
                evidence={"fault_desc": scene.fault_desc, "assert_msg": scene.assert_msg},
            )
        )

    if scene.thread_name:
        hint = THREAD_HINTS.get(scene.thread_name)
        if hint:
            hits.append(
                RuleHit(
                    id="thread_hint",
                    confidence="medium",
                    message=f"线程 {scene.thread_name}：{hint}",
                    evidence={"thread": scene.thread_name, "queue": scene.queue_name},
                )
            )

    if scene.regs.get("R0") in ("0x0", "0x00000000") and fault:
        try:
            if int(fault, 16) <= 0x100:
                hits.append(
                    RuleHit(
                        id="r0_null",
                        confidence="medium",
                        message="R0 为 0 且 Fault 为小偏移，符合空指针基址特征",
                        evidence={"r0": scene.regs.get("R0"), "fault_addr": fault},
                    )
                )
        except ValueError:
            pass

    if scene.mem_hints:
        hits.append(
            RuleHit(
                id="mem_hint",
                confidence="low",
                message="ASS 中出现内存相关源码线索，建议关注堆/释放路径",
                evidence={"hints": scene.mem_hints[:5]},
            )
        )

    return hits


def overall_confidence(hits: List[RuleHit]) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    if not hits:
        return "low"
    return max(hits, key=lambda h: order.get(h.confidence, 0)).confidence
