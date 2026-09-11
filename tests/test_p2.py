# -*- coding: utf-8 -*-
"""时间线 / 栈 / 调用栈 / diff 单元测试。"""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from dumptrace.callstack import build_callstack_candidates
from dumptrace.diff import diff_summaries
from dumptrace.mem_stack import extract_stack, scan_stack_words
from dumptrace.timeline import hms_to_ms, parse_trace_line, render_timeline_txt
from dumptrace.timeline import TimelineEvent, TimelineResult


class TestTimelineParse(unittest.TestCase):
    def test_hms(self) -> None:
        self.assertEqual(hms_to_ms("0:00:03.500"), 3500)

    def test_parse_line(self) -> None:
        line = (
            "123-0       \t0:00:01.000 \t--  \t"
            f"{'camera stream start':<160}\t{'':<64}\t0:00:01.000  \t"
        )
        p = parse_trace_line(line)
        self.assertIsNotNone(p)
        assert p is not None
        sn, ue, content, tick = p
        self.assertEqual(tick, 1000)
        self.assertIn("camera", content)


class TestMemStack(unittest.TestCase):
    def test_extract_and_scan(self) -> None:
        base = 0x80000000
        start = 0x80001000
        end = 0x8000103F
        # 文件从 base 开始；前面填 0x1000 字节
        payload = bytearray(0x1040)
        # 在栈区写入代码地址 0x60127474 与 0x60022f48
        struct.pack_into("<I", payload, 0x1000, 0x60127474)
        struct.pack_into("<I", payload, 0x1004, 0x60022F49)  # thumb bit
        with tempfile.TemporaryDirectory() as td:
            mem = Path(td) / "x.mem"
            mem.write_bytes(payload)
            sl = extract_stack(
                mem,
                stack_start=hex(start),
                stack_end=hex(end),
                mem_base=hex(base),
            )
            self.assertTrue(sl.ok)
            self.assertEqual(sl.length, 0x40)
            hits = scan_stack_words(
                sl.data,
                stack_start=start,
                code_ranges=[(0x60000000, 0x62000000)],
            )
            addrs = {h[1] for h in hits}
            self.assertIn(0x60127474, addrs)
            self.assertIn(0x60022F48, addrs)

            cs = build_callstack_candidates(
                sl.data,
                stack_start=start,
                axf=None,
                code_ranges=[(0x60000000, 0x62000000)],
            )
            self.assertTrue(cs.ok)
            self.assertGreaterEqual(len(cs.candidates), 2)


class TestDiff(unittest.TestCase):
    def test_diff_summaries(self) -> None:
        a = {
            "ok": True,
            "dump_id": "a",
            "thread_name": "T_P_APP",
            "fault_addr": "0x4",
            "exception_addr": "0x1",
            "assert_msg": "x",
            "pc": "0x2",
            "project_version": "P1",
            "exception_symbol": "FOO",
            "rule_ids": ["null_deref"],
            "confidence": "high",
            "log_credibility": "medium",
        }
        b = dict(a)
        b["dump_id"] = "b"
        b["fault_addr"] = "0x8"
        b["exception_symbol"] = "BAR"
        d = diff_summaries(a, b)
        fields = {c["field"] for c in d["changes"]}
        self.assertIn("fault_addr", fields)
        self.assertIn("exception_symbol", fields)
        self.assertFalse(d["identical"])


class TestTimelineRender(unittest.TestCase):
    def test_render(self) -> None:
        tl = TimelineResult(
            ok=True,
            source="test",
            total_lines=1,
            last_tick_ms=1000,
            windows={
                "3s": [
                    TimelineEvent(
                        tick_ms=900,
                        ue_time="0:00:00.900",
                        sn="1-0",
                        content="camera abort",
                        matched_keywords=["camera"],
                    )
                ]
            },
        )
        text = render_timeline_txt(tl)
        self.assertIn("camera abort", text)


if __name__ == "__main__":
    unittest.main()
