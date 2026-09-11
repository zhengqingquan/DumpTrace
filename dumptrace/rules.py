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


def apply_rules(
    scene: AssertScene,
    mem_usage: Any = None,
    rtos_info: Any = None,
    sync_objects: Any = None,
    mmi_state: Any = None,
    *,
    queue_pressure_pct: float = 80.0,
    stack_overflow_pct: float = 90.0,
) -> List[RuleHit]:
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

    msg = (scene.assert_msg or "").lower()
    if "no memory" in msg or "unable to allocate" in msg or "0x10" in msg:
        hits.append(
            RuleHit(
                id="oom_assert",
                confidence="high",
                message="断言提示内存分配失败（No memory / unable to allocate）",
                evidence={"assert_msg": scene.assert_msg},
            )
        )

    overall = None
    if mem_usage is not None:
        overall = getattr(mem_usage, "overall", None)
        if overall is None and isinstance(mem_usage, dict):
            overall = mem_usage.get("overall")
    if isinstance(overall, dict) and overall.get("used_pct") is not None:
        pct = float(overall["used_pct"])
        if pct >= 95:
            hits.append(
                RuleHit(
                    id="mem_pressure",
                    confidence="high",
                    message=f"内存池使用率约 {pct}%（可用 {overall.get('avail')} / 总计 {overall.get('total')}）",
                    evidence=dict(overall),
                )
            )
        elif pct >= 85:
            hits.append(
                RuleHit(
                    id="mem_pressure",
                    confidence="medium",
                    message=f"内存池使用率约 {pct}%，接近耗尽",
                    evidence=dict(overall),
                )
            )

    # 专用池压力
    pools = None
    if mem_usage is not None:
        pools = getattr(mem_usage, "pools", None)
        if pools is None and isinstance(mem_usage, dict):
            pools = mem_usage.get("pools")
    if pools:
        dedicated_hits = []
        for p in pools:
            kind = p.get("kind") if isinstance(p, dict) else getattr(p, "kind", "main")
            if kind != "dedicated":
                continue
            pct = p.get("used_pct") if isinstance(p, dict) else getattr(p, "used_pct", None)
            if pct is None:
                continue
            if float(pct) >= 85:
                dedicated_hits.append(p if isinstance(p, dict) else p.to_dict())
        if dedicated_hits:
            top = max(dedicated_hits, key=lambda x: float(x.get("used_pct") or 0))
            hits.append(
                RuleHit(
                    id="dedicated_pool_pressure",
                    confidence="high" if float(top.get("used_pct") or 0) >= 95 else "medium",
                    message=(
                        f"专用池 {top.get('name')} 使用率约 {top.get('used_pct')}%"
                        f"（{top.get('used')}/{top.get('total')}）"
                    ),
                    evidence={"pools": dedicated_hits[:8]},
                )
            )

    hits.extend(
        _rtos_rules(
            scene,
            rtos_info,
            queue_pressure_pct=queue_pressure_pct,
            stack_overflow_pct=stack_overflow_pct,
        )
    )
    hits.extend(_sync_rules(scene, sync_objects))
    hits.extend(_mmi_rules(mmi_state))
    return hits


def _sync_rules(scene: AssertScene, sync_objects: Any) -> List[RuleHit]:
    if sync_objects is None:
        return []
    hits: List[RuleHit] = []

    def _g(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    held = _g(sync_objects, "held_locks") or []
    waited = _g(sync_objects, "waited") or []

    if held:
        assert_held = [
            h
            for h in held
            if scene.thread_name and _g(h, "owner") == scene.thread_name
        ]
        sample = assert_held or held[:5]
        owner = _g(sample[0], "owner")
        hits.append(
            RuleHit(
                id="lock_held_by_X",
                confidence="medium" if assert_held else "low",
                message=(
                    f"有 {len(held)} 个 Mutex 被持有"
                    + (
                        f"，其中 {len(assert_held)} 个由 Assert 线程 {scene.thread_name} 持有"
                        if assert_held
                        else f"（示例 owner={owner}）"
                    )
                ),
                evidence={
                    "held_count": len(held),
                    "assert_held": assert_held[:8],
                    "sample": held[:8],
                },
            )
        )

    if waited:
        hits.append(
            RuleHit(
                id="waiters_gt_0",
                confidence="medium",
                message=f"有 {len(waited)} 个同步对象存在等待者（TotalSuspended/SuspendList>0）",
                evidence={"waited": waited[:12]},
            )
        )
    return hits


def _mmi_rules(mmi_state: Any) -> List[RuleHit]:
    if mmi_state is None:
        return []
    ok = getattr(mmi_state, "ok", None)
    if ok is None and isinstance(mmi_state, dict):
        ok = mmi_state.get("ok")
    if not ok:
        return []
    overall = getattr(mmi_state, "overall", None)
    if overall is None and isinstance(mmi_state, dict):
        overall = mmi_state.get("overall") or {}
    anim_n = (overall or {}).get("anim_control_count") or 0
    applet = (overall or {}).get("current_applet_name")
    focus = (overall or {}).get("focus_window_name")
    if not applet and not focus and not anim_n:
        return []
    return [
        RuleHit(
            id="mmi_state_present",
            confidence="low",
            message=(
                f"MMI 状态：applet=`{applet}` focus=`{focus}` "
                f"anim_controls={anim_n}"
            ),
            evidence=dict(overall or {}),
        )
    ]


def _rtos_rules(
    scene: AssertScene,
    rtos_info: Any,
    *,
    queue_pressure_pct: float,
    stack_overflow_pct: float,
) -> List[RuleHit]:
    hits: List[RuleHit] = []
    tasks = []
    timers = []
    queues = []
    module_counts: Dict[str, Any] = {}
    if rtos_info is not None:
        tasks = getattr(rtos_info, "tasks", None)
        if tasks is None and isinstance(rtos_info, dict):
            tasks = rtos_info.get("tasks") or []
        timers = getattr(rtos_info, "timers", None)
        if timers is None and isinstance(rtos_info, dict):
            timers = rtos_info.get("timers") or []
        queues = getattr(rtos_info, "queues", None)
        if queues is None and isinstance(rtos_info, dict):
            queues = rtos_info.get("queues") or []
        module_counts = getattr(rtos_info, "timer_module_counts", None) or {}
        if isinstance(rtos_info, dict) and not module_counts:
            module_counts = rtos_info.get("timer_module_counts") or {}

    def _g(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    # 队列压力：当前线程字段或 rtos queues
    q_candidates: List[Dict[str, Any]] = []
    if scene.queue_total and scene.queue_used is not None and scene.queue_total > 0:
        pct = round(100.0 * scene.queue_used / scene.queue_total, 2)
        q_candidates.append(
            {
                "name": scene.queue_name or "current",
                "used": scene.queue_used,
                "total": scene.queue_total,
                "used_pct": pct,
                "source": "current_thread",
            }
        )
    for q in queues or []:
        pct = _g(q, "used_pct")
        if pct is None:
            continue
        q_candidates.append(
            {
                "name": _g(q, "name"),
                "used": _g(q, "used"),
                "total": _g(q, "total"),
                "used_pct": float(pct),
                "source": _g(q, "source"),
                "task_name": _g(q, "task_name"),
            }
        )
    pressured = [q for q in q_candidates if float(q["used_pct"]) >= queue_pressure_pct]
    if pressured:
        top = max(pressured, key=lambda x: float(x["used_pct"]))
        hits.append(
            RuleHit(
                id="queue_pressure",
                confidence="high" if float(top["used_pct"]) >= 95 else "medium",
                message=(
                    f"队列 {top.get('name')} 使用率约 {top.get('used_pct')}%"
                    f"（{top.get('used')}/{top.get('total')}）"
                ),
                evidence={"pressured": pressured[:8], "threshold_pct": queue_pressure_pct},
            )
        )

    if rtos_info is None:
        return hits

    # 栈将溢
    stack_hits = []
    for t in tasks or []:
        pct = _g(t, "stack_used_pct")
        if pct is None:
            continue
        if float(pct) >= stack_overflow_pct:
            stack_hits.append(
                {
                    "name": _g(t, "name"),
                    "task_id": _g(t, "task_id"),
                    "stack_used_pct": pct,
                    "stack_max_used": _g(t, "stack_max_used"),
                    "stack_total": _g(t, "stack_total"),
                }
            )
    if stack_hits:
        top = max(stack_hits, key=lambda x: float(x["stack_used_pct"]))
        hits.append(
            RuleHit(
                id="stack_near_overflow",
                confidence="high" if float(top["stack_used_pct"]) >= 95 else "medium",
                message=(
                    f"线程 {top.get('name')} 栈高水位约 {top.get('stack_used_pct')}%"
                    f"（{top.get('stack_max_used')}/{top.get('stack_total')}）"
                ),
                evidence={"tasks": stack_hits[:10], "threshold_pct": stack_overflow_pct},
            )
        )

    # Assert 线程对齐 / 非运行态
    if scene.thread_name and tasks:
        matched = None
        for t in tasks:
            if _g(t, "name") == scene.thread_name:
                matched = t
                break
            tid = _g(t, "task_id")
            if scene.thread_id and tid and str(tid).lower() == str(scene.thread_id).lower():
                matched = t
                break
        if matched is None:
            hits.append(
                RuleHit(
                    id="assert_thread_not_running",
                    confidence="medium",
                    message=f"任务表中未找到 Assert 线程 {scene.thread_name}",
                    evidence={"thread": scene.thread_name, "thread_id": scene.thread_id},
                )
            )
        else:
            status = (_g(matched, "status") or "").upper()
            is_current = bool(_g(matched, "is_current"))
            blocked = any(
                k in status
                for k in ("QUEUE_SUSP", "SEMAPHORE_SUSP", "EVENT_FLAG", "SUSPENDED", "SLEEP")
            )
            if blocked and not is_current:
                hits.append(
                    RuleHit(
                        id="assert_thread_not_running",
                        confidence="medium",
                        message=(
                            f"Assert 线程 {scene.thread_name} 在任务表中为 {status}，非运行标记"
                        ),
                        evidence={
                            "thread": scene.thread_name,
                            "status": status,
                            "task_id": _g(matched, "task_id"),
                        },
                    )
                )
            if blocked:
                hits.append(
                    RuleHit(
                        id="task_blocked",
                        confidence="low",
                        message=f"线程 {scene.thread_name} 状态 {status or 'unknown'}（等待/挂起类）",
                        evidence={
                            "thread": scene.thread_name,
                            "status": status,
                            "is_current": is_current,
                        },
                    )
                )

    # 周期定时器活跃
    periodic = [t for t in (timers or []) if _g(t, "periodic") or int(_g(t, "re_init_ticks") or 0) > 0]
    if periodic:
        names = [_g(t, "name") for t in periodic[:12]]
        hits.append(
            RuleHit(
                id="periodic_timer_active",
                confidence="low",
                message=f"存在 {len(periodic)} 个周期定时器（re_init>0），模块分布 {dict(module_counts or {})}",
                evidence={
                    "count": len(periodic),
                    "sample_names": names,
                    "module_counts": dict(module_counts or {}),
                },
            )
        )

    return hits


def overall_confidence(hits: List[RuleHit]) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    if not hits:
        return "low"
    return max(hits, key=lambda h: order.get(h.confidence, 0)).confidence
