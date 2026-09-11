# -*- coding: utf-8 -*-
"""从 .ass 解析全任务表 / 栈水位 / 队列 / 定时器列表（P0）。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 默认：按定时器名子串归类（通用，不含客户业务专名）
DEFAULT_TIMER_MODULES: Dict[str, List[str]] = {
    "display": ["MMK", "LCD", "period", "GIF", "UI"],
    "camera": ["DCAMERA", "ISP", "IMG", "CAMERA"],
    "audio": ["AUDIO", "audio"],
    "network": ["ATC", "SIP", "NET", "MNPS", "TCP", "UDP", "WLAN"],
    "usb": ["USB", "UCOM"],
    "power": ["CHG", "IDLE", "GPIO", "SLEEP", "DoIdle"],
    "system": ["RTOS", "thread_timer", "MdLog", "System Timer"],
}

QUEUE_PRESSURE_PCT = 80.0
STACK_OVERFLOW_PCT = 90.0


@dataclass
class TaskEntry:
    task_id: str
    name: str
    tcb_addr: Optional[str] = None
    current_pc: Optional[str] = None
    queue_all: Optional[int] = None
    queue_avail: Optional[int] = None
    queue_used: Optional[int] = None
    queue_used_pct: Optional[float] = None
    status: Optional[str] = None
    priority: Optional[int] = None
    is_current: bool = False
    # 来自 Stack info 的合并字段
    stack_total: Optional[int] = None
    stack_max_used: Optional[int] = None
    stack_available: Optional[int] = None
    stack_used_pct: Optional[float] = None
    stack_cur_ptr: Optional[str] = None
    stack_start: Optional[str] = None
    stack_end: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QueueEntry:
    name: str
    total: int
    used: int
    available: int
    used_pct: Optional[float]
    source: str  # current_thread / tasks
    task_id: Optional[str] = None
    task_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimerEntry:
    name: str
    rem_ticks: int
    re_init_ticks: int
    cur_ptr: Optional[str] = None
    next_ptr: Optional[str] = None
    pre_ptr: Optional[str] = None
    cur_ticks: Optional[int] = None
    scope: str = "global"  # global / active_threads
    modules: List[str] = field(default_factory=list)
    periodic: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RtosInfoReport:
    ok: bool
    tasks: List[TaskEntry] = field(default_factory=list)
    queues: List[QueueEntry] = field(default_factory=list)
    timers: List[TimerEntry] = field(default_factory=list)
    suspicious_tasks: List[Dict[str, Any]] = field(default_factory=list)
    timer_module_counts: Dict[str, int] = field(default_factory=dict)
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "overall": self.overall,
            "tasks": [t.to_dict() for t in self.tasks],
            "queues": [q.to_dict() for q in self.queues],
            "timers": [t.to_dict() for t in self.timers],
            "suspicious_tasks": list(self.suspicious_tasks),
            "timer_module_counts": dict(self.timer_module_counts),
            "warnings": list(self.warnings),
        }


def _pct(used: int, total: int) -> Optional[float]:
    if total <= 0:
        return None
    return round(100.0 * used / total, 2)


def _norm_hex(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().lower()
    if not v.startswith("0x"):
        v = "0x" + v
    try:
        return f"0x{int(v, 16):x}"
    except ValueError:
        return value.strip()


def _normalize_dump_text(data: bytes) -> str:
    """保留制表符语义：转空格，去掉串口菜单提示符，便于按行正则。"""
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "")
    text = text.replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    text = re.sub(r"[ \t]{2,}", "  ", text)
    return text


def _slice_section(text: str, start: str, end_markers: List[str]) -> Optional[str]:
    patterns = [start]
    if "information" in start.lower():
        patterns.append(start.replace("information", "infomation").replace("Information", "Infomation"))
    m = None
    for pat in patterns:
        m = re.search(re.escape(pat), text, re.I)
        if m:
            break
    if not m:
        return None
    start_at = m.end()
    end = len(text)
    for em in end_markers:
        j = re.search(re.escape(em), text[start_at + 10 :], re.I)
        if j:
            end = min(end, start_at + 10 + j.start())
    return text[start_at:end]


_TASK_FULL_RE = re.compile(
    r"^(?:\*{2,})?(0x[0-9A-Fa-f]+)\s+"
    r"(.+?)\s+"
    r"(0x[0-9A-Fa-f]+)\s+"
    r"(0x[0-9A-Fa-f]+)\s+"
    r"(\d+)\s+(\d+)\s+"
    r"(TX_[A-Z0-9_]+)\s+(\d+)\s*$",
    re.M | re.I,
)
_TASK_TRUNC_RE = re.compile(
    r"^(\*{2,})(0x[0-9A-Fa-f]+)\s+"
    r"(.+?)\s+"
    r"(0x[0-9A-Fa-f]+)\s+"
    r"(\d+)\s*$",
    re.M | re.I,
)
_STACK_ROW_RE = re.compile(
    r"^(0x[0-9A-Fa-f]+)\s+"
    r"(.+?)\s+"
    r"(\d+)\s+(\d+)\s+(\d+)\s+"
    r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s*$",
    re.M | re.I,
)
_TIMER_ROW_RE = re.compile(
    r"(?:^|\n)\s*(?:(\d+)\s+)?"
    r"([A-Za-z_][A-Za-z0-9_ ]*?)\s+"
    r"(\d+)\s+(\d+)\s+"
    r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)",
    re.I,
)
_CURRENT_QUEUE_RE = re.compile(
    r"Current thread info:.*?"
    r"Name:\s*([^\r\n]+).*?"
    r"Queue_Name:\s*([^\r\n]+).*?"
    r"Queue_Total:\s*(\d+).*?"
    r"Queue_Used:\s*(\d+).*?"
    r"Queue_Available:\s*(\d+)",
    re.S | re.I,
)
_CURRENT_THREAD_ID_NAME_RE = re.compile(
    r"Current thread info:.*?"
    r"ID:\s*(0x[0-9A-Fa-f]+).*?"
    r"Name:\s*([^\r\n]+)",
    re.S | re.I,
)


def _name_looks_truncated(name: str) -> bool:
    s = (name or "").strip()
    if not s:
        return True
    if s.startswith("[") and "]" not in s:
        return True
    if s.startswith("(") and ")" not in s:
        return True
    return False


def _repair_bracket_name(name: str, text: str) -> Optional[str]:
    """缺右括号时，在全文找 name+] 的完整形式。"""
    s = (name or "").strip()
    if not s.startswith("[") or "]" in s:
        return None
    m = re.search(re.escape(s) + r"\]", text)
    return m.group(0) if m else None


def _enrich_task_names(tasks: List[TaskEntry], text: str) -> None:
    """补全 Tasks 表里被 ******** 截断的当前线程名等。"""
    cur_id: Optional[str] = None
    cur_name: Optional[str] = None
    m = _CURRENT_THREAD_ID_NAME_RE.search(text)
    if m:
        cur_id = _norm_hex(m.group(1)) or m.group(1)
        cur_name = m.group(2).strip() or None

    for t in tasks:
        if cur_id and cur_name and t.task_id == cur_id:
            if t.name != cur_name and (
                _name_looks_truncated(t.name or "")
                or t.is_current
                or (t.name and cur_name.startswith(t.name))
            ):
                t.name = cur_name
            continue
        if _name_looks_truncated(t.name or ""):
            fixed = _repair_bracket_name(t.name or "", text)
            if fixed:
                t.name = fixed


def _classify_timer(name: str, modules: Dict[str, List[str]]) -> List[str]:
    hit: List[str] = []
    upper = name.upper()
    for mod, keys in modules.items():
        for k in keys:
            if k.upper() in upper:
                hit.append(mod)
                break
    return hit


def parse_rtos_info(
    path: Path,
    *,
    assert_thread_name: Optional[str] = None,
    assert_thread_id: Optional[str] = None,
    timer_modules: Optional[Dict[str, List[str]]] = None,
    queue_pressure_pct: float = QUEUE_PRESSURE_PCT,
    stack_overflow_pct: float = STACK_OVERFLOW_PCT,
) -> RtosInfoReport:
    try:
        data = path.read_bytes()
    except OSError as e:
        return RtosInfoReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _normalize_dump_text(data)
    report = RtosInfoReport(ok=False)
    modules = timer_modules or DEFAULT_TIMER_MODULES

    tasks = _parse_tasks(text)
    _enrich_task_names(tasks, text)
    stacks = _parse_stacks(text)
    _merge_stacks(tasks, stacks)
    report.tasks = tasks

    if not tasks:
        report.warnings.append("no Tasks info table found in .ass")
    if not stacks:
        report.warnings.append("no Stack info table found in .ass")

    report.queues = _parse_queues(text, tasks)
    report.timers = _parse_timers(text, modules)

    if not report.timers:
        report.warnings.append("no timer list found in .ass")

    report.suspicious_tasks = _suspicious(
        tasks,
        assert_thread_name=assert_thread_name,
        assert_thread_id=assert_thread_id,
        queue_pressure_pct=queue_pressure_pct,
        stack_overflow_pct=stack_overflow_pct,
    )
    report.timer_module_counts = _timer_module_counts(report.timers)

    periodic_n = sum(1 for t in report.timers if t.periodic)
    pressured_q = [
        q
        for q in report.queues
        if q.used_pct is not None and q.used_pct >= queue_pressure_pct
    ]
    report.overall = {
        "task_count": len(tasks),
        "timer_count": len(report.timers),
        "periodic_timer_count": periodic_n,
        "queue_count": len(report.queues),
        "pressured_queue_count": len(pressured_q),
        "suspicious_count": len(report.suspicious_tasks),
        "current_task": next((t.name for t in tasks if t.is_current), None),
    }

    report.ok = bool(tasks or report.timers or report.queues)
    if not report.ok and not report.warnings:
        report.warnings.append("no rtos tasks/timers/queues found in .ass")
    return report


def _parse_tasks(text: str) -> List[TaskEntry]:
    section = _slice_section(
        text,
        "Tasks info:",
        ["Stack info:", "timer infomation", "Timer list", "Semaphore infomation", "Mutex"],
    )
    if not section:
        return []
    # 去掉表头
    body = re.sub(
        r"Task_ID\s+Name\s+Tcb_Addr\s+Current_PC\s+Queue_All\s+Queue_Avail\s*",
        "",
        section,
        count=1,
        flags=re.I,
    )
    out: List[TaskEntry] = []
    seen: set = set()
    for m in _TASK_FULL_RE.finditer(body):
        q_all, q_avail = int(m.group(5)), int(m.group(6))
        used = max(0, q_all - q_avail)
        tid = _norm_hex(m.group(1)) or m.group(1)
        name = m.group(2).strip()
        key = (tid, name)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            TaskEntry(
                task_id=tid,
                name=name,
                tcb_addr=_norm_hex(m.group(3)),
                current_pc=_norm_hex(m.group(4)),
                queue_all=q_all,
                queue_avail=q_avail,
                queue_used=used,
                queue_used_pct=_pct(used, q_all),
                status=m.group(7).upper(),
                priority=int(m.group(8)),
                is_current=False,
            )
        )
    for m in _TASK_TRUNC_RE.finditer(body):
        tid = _norm_hex(m.group(2)) or m.group(2)
        name = m.group(3).strip()
        key = (tid, name)
        # 截断行：当前异常线程，补全或覆盖
        entry = TaskEntry(
            task_id=tid,
            name=name,
            tcb_addr=_norm_hex(m.group(4)),
            priority=int(m.group(5)),
            is_current=True,
        )
        replaced = False
        for i, old in enumerate(out):
            if old.task_id == tid and old.name == name:
                old.is_current = True
                if old.priority is None:
                    old.priority = entry.priority
                replaced = True
                break
        if not replaced:
            out.append(entry)
            seen.add(key)
    return out


def _parse_stacks(text: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
    section = _slice_section(
        text,
        "Stack info:",
        [
            "timer infomation",
            "Timer list",
            "Print stack",
            "Semaphore infomation",
            "Mutex",
            "callback",
            "Tasks info:",
        ],
    )
    if not section:
        return {}
    body = re.sub(
        r"Task_ID\s+Name\s+TotalSize\s+Max_Used\s+Available\s+Cur_Ptr\s+Start\s+End\s*",
        "",
        section,
        count=1,
        flags=re.I,
    )
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for m in _STACK_ROW_RE.finditer(body):
        tid = _norm_hex(m.group(1)) or m.group(1)
        name = m.group(2).strip()
        total, max_used, avail = int(m.group(3)), int(m.group(4)), int(m.group(5))
        out[(tid, name)] = {
            "stack_total": total,
            "stack_max_used": max_used,
            "stack_available": avail,
            "stack_used_pct": _pct(max_used, total),
            "stack_cur_ptr": _norm_hex(m.group(6)),
            "stack_start": _norm_hex(m.group(7)),
            "stack_end": _norm_hex(m.group(8)),
        }
    return out


def _merge_stacks(tasks: List[TaskEntry], stacks: Dict[Tuple[str, str], Dict[str, Any]]) -> None:
    by_name: Dict[str, Dict[str, Any]] = {}
    for (tid, name), st in stacks.items():
        by_name[name] = st
        by_name[f"{tid}|{name}"] = st
    for t in tasks:
        st = stacks.get((t.task_id, t.name)) or by_name.get(t.name)
        if not st:
            continue
        for k, v in st.items():
            setattr(t, k, v)


def _parse_queues(text: str, tasks: List[TaskEntry]) -> List[QueueEntry]:
    queues: List[QueueEntry] = []
    m = _CURRENT_QUEUE_RE.search(text)
    if m:
        total, used, avail = int(m.group(3)), int(m.group(4)), int(m.group(5))
        queues.append(
            QueueEntry(
                name=m.group(2).strip(),
                total=total,
                used=used,
                available=avail,
                used_pct=_pct(used, total),
                source="current_thread",
                task_name=m.group(1).strip(),
            )
        )
    for t in tasks:
        if t.queue_all is None:
            continue
        qname = f"Q@{t.name}"
        queues.append(
            QueueEntry(
                name=qname,
                total=t.queue_all,
                used=t.queue_used or 0,
                available=t.queue_avail if t.queue_avail is not None else 0,
                used_pct=t.queue_used_pct,
                source="tasks",
                task_id=t.task_id,
                task_name=t.name,
            )
        )
    return queues


def _parse_timers(text: str, modules: Dict[str, List[str]]) -> List[TimerEntry]:
    timers: List[TimerEntry] = []
    sections = [
        ("timer infomation", "global", ["Active Threads", "Semaphore", "Mutex", "Event"]),
        (
            "Active Threads' timer infomation",
            "active_threads",
            ["Semaphore", "Mutex", "Event", "callback"],
        ),
        (
            "Active Threads' timer information",
            "active_threads",
            ["Semaphore", "Mutex", "Event", "callback"],
        ),
    ]
    # 也兼容正确拼写
    sections.insert(
        0,
        ("timer information", "global", ["Active Threads", "Semaphore", "Mutex", "Event"]),
    )
    seen_scopes = set()
    for marker, scope, ends in sections:
        if scope in seen_scopes and scope == "active_threads":
            # 已解析过 active
            pass
        section = _slice_section(text, marker, ends)
        if not section:
            continue
        if scope == "global" and "global" in seen_scopes:
            continue
        if scope == "active_threads" and "active_threads" in seen_scopes:
            continue
        seen_scopes.add(scope)
        # 去掉表头关键字行
        body = re.sub(
            r"cur_ticks\s+name\s+rem_ticks\s+re_init_ticks\s+\S+\s+\S+\s+\S+",
            "",
            section,
            count=1,
            flags=re.I,
        )
        for m in _TIMER_ROW_RE.finditer(body):
            name = m.group(2).strip()
            if not name or name.lower() in ("name", "cur_ticks", "rem_ticks"):
                continue
            rem, rein = int(m.group(3)), int(m.group(4))
            entry = TimerEntry(
                name=name,
                rem_ticks=rem,
                re_init_ticks=rein,
                cur_ptr=_norm_hex(m.group(5)),
                next_ptr=_norm_hex(m.group(6)),
                pre_ptr=_norm_hex(m.group(7)),
                cur_ticks=int(m.group(1)) if m.group(1) else None,
                scope=scope,
                modules=_classify_timer(name, modules),
                periodic=rein > 0,
            )
            timers.append(entry)
    return timers


def _suspicious(
    tasks: List[TaskEntry],
    *,
    assert_thread_name: Optional[str],
    assert_thread_id: Optional[str],
    queue_pressure_pct: float,
    stack_overflow_pct: float,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    aid = _norm_hex(assert_thread_id) if assert_thread_id else None
    for t in tasks:
        reasons: List[str] = []
        if t.is_current:
            reasons.append("current_assert_thread")
        if assert_thread_name and t.name == assert_thread_name:
            reasons.append("assert_thread_name")
        if aid and t.task_id == aid:
            reasons.append("assert_thread_id")
        if t.stack_used_pct is not None and t.stack_used_pct >= stack_overflow_pct:
            reasons.append(f"stack_high:{t.stack_used_pct}%")
        if t.queue_used_pct is not None and t.queue_used_pct >= queue_pressure_pct:
            reasons.append(f"queue_high:{t.queue_used_pct}%")
        if not reasons:
            continue
        out.append(
            {
                "task_id": t.task_id,
                "name": t.name,
                "status": t.status,
                "priority": t.priority,
                "stack_used_pct": t.stack_used_pct,
                "queue_used_pct": t.queue_used_pct,
                "reasons": reasons,
            }
        )
    return out


def _timer_module_counts(timers: List[TimerEntry]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for t in timers:
        if not t.modules:
            counts["other"] = counts.get("other", 0) + 1
            continue
        for m in t.modules:
            counts[m] = counts.get(m, 0) + 1
    return counts


def render_tasks_txt(report: RtosInfoReport) -> str:
    lines = [
        f"# tasks ok={report.ok} count={len(report.tasks)}",
        f"# overall={report.overall}",
    ]
    for w in report.warnings:
        lines.append(f"# warn: {w}")
    lines += ["", "## tasks"]
    if not report.tasks:
        lines.append("(none)")
    for t in report.tasks:
        cur = "*" if t.is_current else " "
        lines.append(
            f"{cur} {t.task_id} {t.name}: status={t.status} prio={t.priority} "
            f"pc={t.current_pc} q={t.queue_used}/{t.queue_all} "
            f"stack_max={t.stack_max_used}/{t.stack_total} ({t.stack_used_pct}%)"
        )
    lines += ["", "## suspicious"]
    if not report.suspicious_tasks:
        lines.append("(none)")
    for s in report.suspicious_tasks:
        lines.append(
            f"- {s.get('name')} ({s.get('task_id')}): {', '.join(s.get('reasons') or [])}"
        )
    lines += ["", "## queues"]
    if not report.queues:
        lines.append("(none)")
    for q in report.queues:
        lines.append(
            f"- [{q.source}] {q.name}: used={q.used}/{q.total} "
            f"avail={q.available} used_pct={q.used_pct}% task={q.task_name}"
        )
    return "\n".join(lines) + "\n"


def render_timers_txt(report: RtosInfoReport) -> str:
    lines = [
        f"# timers ok={report.ok} count={len(report.timers)}",
        f"# module_counts={report.timer_module_counts}",
    ]
    for w in report.warnings:
        if "timer" in w.lower():
            lines.append(f"# warn: {w}")
    lines += ["", "## timers"]
    if not report.timers:
        lines.append("(none)")
    # 周期定时器优先，再按 rem 升序
    ordered = sorted(
        report.timers,
        key=lambda t: (0 if t.periodic else 1, t.rem_ticks, t.name),
    )
    for t in ordered:
        mods = ",".join(t.modules) if t.modules else "-"
        lines.append(
            f"- [{t.scope}] {t.name}: rem={t.rem_ticks} period={t.re_init_ticks} "
            f"periodic={t.periodic} modules={mods} cur={t.cur_ptr}"
        )
    # Top 周期回调名（本格式无函数指针，按名归类）
    lines += ["", "## periodic_by_module"]
    if not report.timer_module_counts:
        lines.append("(none)")
    else:
        for mod, n in sorted(report.timer_module_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"- {mod}: {n}")
    return "\n".join(lines) + "\n"
