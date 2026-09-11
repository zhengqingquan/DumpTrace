# -*- coding: utf-8 -*-
"""从 .ass 解析 Mutex / Semaphore / Event 同步原语（P1）。"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SyncObject:
    kind: str  # mutex / semaphore / event
    name: str
    owner: Optional[str] = None
    ownership_count: Optional[int] = None
    counter: Optional[int] = None
    current_flag: Optional[str] = None
    total_suspended: int = 0
    waiters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SyncObjectsReport:
    ok: bool
    mutexes: List[SyncObject] = field(default_factory=list)
    semaphores: List[SyncObject] = field(default_factory=list)
    events: List[SyncObject] = field(default_factory=list)
    held_locks: List[Dict[str, Any]] = field(default_factory=list)
    waited: List[Dict[str, Any]] = field(default_factory=list)
    overall: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "overall": self.overall,
            "mutexes": [m.to_dict() for m in self.mutexes],
            "semaphores": [s.to_dict() for s in self.semaphores],
            "events": [e.to_dict() for e in self.events],
            "held_locks": list(self.held_locks),
            "waited": list(self.waited),
            "warnings": list(self.warnings),
        }


def _normalize(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", "").replace("\t", " ")
    text = re.sub(r"\n\s*>\s*", "\n", text)
    text = re.sub(r"[^\x20-\x7E\n]+", "\n", text)
    # 保留多空格以便 Mutex 定宽列对齐；勿压缩空白
    return text


def _slice(text: str, start: str, ends: List[str]) -> Optional[str]:
    patterns = [start]
    if "information" in start.lower():
        patterns.append(
            start.replace("information", "infomation").replace(
                "Information", "Infomation"
            )
        )
    m = None
    for pat in patterns:
        m = re.search(re.escape(pat), text, re.I)
        if m:
            break
    if not m:
        return None
    start_at = m.end()
    end = len(text)
    for em in ends:
        # 仅在行首匹配结束标记，避免名字中含子串（如 Flash OPERATION SEMAPHORE）
        j = re.search(r"(?m)^\s*" + re.escape(em), text[start_at + 20 :], re.I)
        if j:
            end = min(end, start_at + 20 + j.start())
    return text[start_at:end]


_MUTEX_ROW_RE = re.compile(
    r"^([A-Za-z0-9_\[\] \-/.]+?)\s+"
    r"(\[No Owner\]|[A-Za-z0-9_]+)\s+"
    r"(\d+)\s+(\d+)\s*$",
    re.M,
)
_SEM_ROW_RE = re.compile(
    r"^([A-Za-z0-9_ \[\]\-/]+?)\s+(\d+)\s*$",
    re.M,
)
_SEM_WAIT_RE = re.compile(
    r"^Suspend Task_Name\s*:\s*([A-Za-z0-9_]+)\s*$",
    re.M | re.I,
)
_EVENT_ROW_RE = re.compile(
    r"^([A-Za-z0-9_ \-!.]+?)\s+([0-9A-Fa-fx]+)\s+(\d+)\s*$",
    re.M | re.I,
)
_EVENT_WAITER_RE = re.compile(
    r"^\s{10,}([A-Za-z0-9_]+)\s*$",
    re.M,
)


def parse_sync_objects(path: Path) -> SyncObjectsReport:
    try:
        data = path.read_bytes()
    except OSError as e:
        return SyncObjectsReport(ok=False, warnings=[f"read ass failed: {e}"])

    text = _normalize(data)
    report = SyncObjectsReport(ok=False)

    report.mutexes = _parse_mutexes(text)
    report.semaphores = _parse_semaphores(text)
    report.events = _parse_events(text)

    if not report.mutexes:
        report.warnings.append("no Mutex Information table found in .ass")
    if not report.semaphores:
        report.warnings.append("no Semaphore list found in .ass")
    if not report.events:
        report.warnings.append("no Event Information table found in .ass")

    held: List[Dict[str, Any]] = []
    waited: List[Dict[str, Any]] = []
    for m in report.mutexes:
        if m.owner and m.owner != "[No Owner]":
            held.append(
                {
                    "kind": "mutex",
                    "name": m.name,
                    "owner": m.owner,
                    "ownership_count": m.ownership_count,
                    "total_suspended": m.total_suspended,
                }
            )
        if m.total_suspended > 0 or m.waiters:
            waited.append(
                {
                    "kind": "mutex",
                    "name": m.name,
                    "owner": m.owner,
                    "total_suspended": m.total_suspended,
                    "waiters": list(m.waiters),
                }
            )
    for s in report.semaphores:
        if s.waiters or s.total_suspended > 0:
            waited.append(
                {
                    "kind": "semaphore",
                    "name": s.name,
                    "counter": s.counter,
                    "total_suspended": s.total_suspended,
                    "waiters": list(s.waiters),
                }
            )
    for e in report.events:
        if e.total_suspended > 0 or e.waiters:
            waited.append(
                {
                    "kind": "event",
                    "name": e.name,
                    "current_flag": e.current_flag,
                    "total_suspended": e.total_suspended,
                    "waiters": list(e.waiters),
                }
            )

    report.held_locks = held
    report.waited = waited
    report.overall = {
        "mutex_count": len(report.mutexes),
        "semaphore_count": len(report.semaphores),
        "event_count": len(report.events),
        "held_count": len(held),
        "waited_count": len(waited),
    }
    report.ok = bool(report.mutexes or report.semaphores or report.events)
    return report


def _parse_mutexes(text: str) -> List[SyncObject]:
    section = _slice(
        text,
        "Mutex Information:",
        [
            "ALL created Threads",
            "timer infomation:",
            "timer information:",
            "Semaphore infomation:",
            "Semaphore information:",
            "Event Information:",
            "s_handle_list",
        ],
    )
    if not section:
        return []
    body = re.sub(
        r"Name\s+Owner\s+TotalSuspended\s+OwnershipCount\s+SuspendList\s*",
        "",
        section,
        count=1,
        flags=re.I,
    )
    out: List[SyncObject] = []
    for raw in body.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        # 定宽：Name(30) Owner(20) 后为数字列（对齐真实 ASS 表头）
        if len(line) >= 50 and re.search(r"\d+\s+\d+", line[50:]):
            name = line[:30].strip()
            owner = line[30:50].strip() or "[No Owner]"
            nums = re.findall(r"\d+", line[50:])
            if name.lower() == "name" or "Owner" in name:
                continue
            if len(nums) < 2:
                continue
            out.append(
                SyncObject(
                    kind="mutex",
                    name=name,
                    owner=owner,
                    total_suspended=int(nums[0]),
                    ownership_count=int(nums[1]),
                )
            )
            continue
        m = _MUTEX_ROW_RE.match(line.strip())
        if not m:
            continue
        name = m.group(1).strip()
        if name.lower() == "name" or "Owner" in name:
            continue
        out.append(
            SyncObject(
                kind="mutex",
                name=name,
                owner=m.group(2).strip(),
                total_suspended=int(m.group(3)),
                ownership_count=int(m.group(4)),
            )
        )
    return out


def _parse_semaphores(text: str) -> List[SyncObject]:
    section = _slice(
        text,
        "Semaphore infomation:",
        [
            "s_handle_list",
            "Mutex Information",
            "Event Information",
            "====",
            "MMI",
        ],
    )
    if not section:
        section = _slice(
            text,
            "Semaphore information:",
            ["s_handle_list", "Mutex Information", "Event Information", "===="],
        )
    if not section:
        return []
    body = re.sub(r"Name\s+Counter\s*", "", section, count=1, flags=re.I)
    out: List[SyncObject] = []
    # 按行扫：信号量行后可跟 Suspend Task_Name
    lines = body.splitlines()
    current: Optional[SyncObject] = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        wm = _SEM_WAIT_RE.match(line)
        if wm and current is not None:
            w = wm.group(1)
            if w not in current.waiters:
                current.waiters.append(w)
            current.total_suspended = max(current.total_suspended, len(current.waiters))
            continue
        sm = _SEM_ROW_RE.match(line)
        if not sm:
            continue
        name = sm.group(1).strip()
        if name.lower() in ("name", "counter") or name.startswith("Suspend"):
            continue
        # 过滤误匹配的表头尾巴
        if len(name) > 80:
            continue
        current = SyncObject(
            kind="semaphore",
            name=name,
            counter=int(sm.group(2)),
        )
        out.append(current)
    return out


def _parse_events(text: str) -> List[SyncObject]:
    section = _slice(
        text,
        "Event Information:",
        [
            "Mutex Information",
            "Semaphore",
            "timer",
            "s_handle_list",
            "Tasks info",
        ],
    )
    if not section:
        return []
    body = re.sub(
        r"Name\s+CurrentFlag\s+TotalSuspended\s+SuspendList\s*",
        "",
        section,
        count=1,
        flags=re.I,
    )
    out: List[SyncObject] = []
    current: Optional[SyncObject] = None
    for line in body.splitlines():
        raw = line.rstrip()
        if not raw.strip():
            continue
        stripped = raw.strip()
        em = _EVENT_ROW_RE.match(stripped)
        if em:
            name = em.group(1).strip()
            if name.lower() == "name":
                continue
            flag = em.group(2)
            if flag.lower().startswith("0x"):
                flag_n = flag.lower()
            else:
                try:
                    flag_n = f"0x{int(flag, 16):x}"
                except ValueError:
                    flag_n = flag
            current = SyncObject(
                kind="event",
                name=name,
                current_flag=flag_n,
                total_suspended=int(em.group(3)),
            )
            out.append(current)
            continue
        # 挂起列表续行：单独任务名（可缩进）
        if current is not None and re.fullmatch(r"[A-Za-z0-9_]+", stripped):
            if stripped.lower() in (
                "name",
                "currentflag",
                "totalsuspended",
                "suspendlist",
            ):
                continue
            if stripped not in current.waiters:
                current.waiters.append(stripped)
    return out


def render_sync_objects_txt(report: SyncObjectsReport) -> str:
    lines = [
        f"# sync_objects ok={report.ok}",
        f"# overall={report.overall}",
    ]
    for w in report.warnings:
        lines.append(f"# warn: {w}")
    lines += ["", "## held_locks"]
    if not report.held_locks:
        lines.append("(none)")
    for h in report.held_locks:
        lines.append(
            f"- {h.get('name')}: owner={h.get('owner')} "
            f"count={h.get('ownership_count')} suspended={h.get('total_suspended')}"
        )
    lines += ["", "## waited"]
    if not report.waited:
        lines.append("(none)")
    for w in report.waited:
        lines.append(
            f"- [{w.get('kind')}] {w.get('name')}: suspended={w.get('total_suspended')} "
            f"waiters={w.get('waiters')}"
        )
    lines += ["", "## mutexes"]
    for m in report.mutexes[:80]:
        lines.append(
            f"- {m.name}: owner={m.owner} ownership={m.ownership_count} "
            f"suspended={m.total_suspended}"
        )
    if len(report.mutexes) > 80:
        lines.append(f"... ({len(report.mutexes) - 80} more)")
    lines += ["", "## semaphores"]
    for s in report.semaphores[:80]:
        lines.append(
            f"- {s.name}: counter={s.counter} waiters={s.waiters}"
        )
    if len(report.semaphores) > 80:
        lines.append(f"... ({len(report.semaphores) - 80} more)")
    lines += ["", "## events"]
    for e in report.events[:80]:
        lines.append(
            f"- {e.name}: flag={e.current_flag} suspended={e.total_suspended} "
            f"waiters={e.waiters}"
        )
    if len(report.events) > 80:
        lines.append(f"... ({len(report.events) - 80} more)")
    return "\n".join(lines) + "\n"
