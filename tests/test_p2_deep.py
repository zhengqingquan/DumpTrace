# -*- coding: utf-8 -*-
"""P2：时间线聚类 / 回调列表 / PS / 堆加深测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dumptrace.ass_parser import AssertScene
from dumptrace.callbacks import parse_callbacks
from dumptrace.mem_usage import parse_mem_usage
from dumptrace.ps_info import parse_ps_info
from dumptrace.rules import apply_rules
from dumptrace.timeline import (
    TimelineEvent,
    TimelineResult,
    _apply_module_clustering,
    DEFAULT_TIMELINE_MODULES,
)

SAMPLE_CALLBACK_ASS = b"""
Exception at 0x6012726a
ASSERT(Abort exception handler !)
Callback Function List:
Current thread callback list:
	Entry at [0x6012726a]
	Entry at [0x6039b228]
	Entry at [0x8095b288]
***Reach top of stack.***
Task 0 (System Timer Thread):
	Entry at [0x8094e8ba]
	Entry at [0x8095b288]
***Reach top of stack ***
Task 100 (RTOS_Manage):
	Entry at [0x8095e294]
***Reach top of stack ***
Mutex Information:
"""

SAMPLE_PS_ASS = b"""
PS tasks queue information:
Name                Used   Total
PS_MM_QUEUE         90     100
PS_SM_QUEUE         2      50
PS function call stack:
	Entry at [0x60100000]
	Entry at [0x60100100]
Mutex Information:
"""

SAMPLE_HEAP_ASS = b"""
Allocated memory info:
No.      Size     FileName (Line)
1        1000     demo_leak.c (Line 10),addr:80a70000
2        2000     demo_leak.c (Line 20),addr:80a71000
3        500      demo_leak.c (Line 30),addr:80a72000
4        100      other.c (Line 1),addr:80a73000
================== System Space Information ==============
 Begin Address   End Address    Total_Num   Avail_Num   Max_Used   Threshold
 0x80ae1cf4      0x80e65cf4     1000000      50000       950000      65536
 --------------------------------------------------------------
 Start_Addr   End_Addr       Size        State      File_Name(Line)
 0x80ae1cf4   0x80ae5d18     16420  ALLOC        demo_leak.c(10)
 0x80ae5d18   0x80ae5e18     256    FREE         (0)
"""


class TestCallbacks(unittest.TestCase):
    def test_parse_and_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cb.ass"
            path.write_bytes(SAMPLE_CALLBACK_ASS)
            report = parse_callbacks(
                path, assert_addrs=[("exception", "0x6012726a"), ("pc", "0x60022f48")]
            )
            self.assertTrue(report.ok)
            self.assertGreaterEqual(len(report.tasks), 2)
            self.assertIsNotNone(report.current)
            self.assertGreaterEqual(len(report.current.entries), 3)
            self.assertGreaterEqual(report.overlap_count, 1)
            hits = apply_rules(AssertScene(), callbacks=report)
            ids = {h.id for h in hits}
            self.assertIn("callback_list_present", ids)
            self.assertIn("callback_assert_overlap", ids)


class TestPsInfo(unittest.TestCase):
    def test_parse_ps_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ps.ass"
            path.write_bytes(SAMPLE_PS_ASS)
            report = parse_ps_info(path)
            self.assertTrue(report.ok)
            self.assertFalse(report.skipped)
            self.assertEqual(len(report.queues), 2)
            self.assertTrue(report.pressured)
            self.assertGreaterEqual(len(report.stack_frames), 2)
            hits = apply_rules(AssertScene(), ps_info=report)
            self.assertTrue(any(h.id == "ps_queue_pressure" for h in hits))

    def test_skip_menu_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "menu.ass"
            path.write_bytes(
                b"j. Print PS tasks queue info\n"
                b"k. Print PS function call stack\n"
                b"Current Version:\n"
            )
            report = parse_ps_info(path)
            self.assertTrue(report.skipped)
            self.assertFalse(report.ok)


class TestTimelineCluster(unittest.TestCase):
    def test_storyline(self) -> None:
        tl = TimelineResult(ok=True)
        tl.windows["10s"] = [
            TimelineEvent(1, "t", "1", "camera preview start", ["camera"]),
            TimelineEvent(2, "t", "2", "camera encode frame", ["camera"]),
            TimelineEvent(3, "t", "3", "display refresh", ["display"]),
        ]
        _apply_module_clustering(tl, DEFAULT_TIMELINE_MODULES)
        self.assertIn("camera", tl.module_counts)
        self.assertIn("camera", tl.storyline)
        hits = apply_rules(AssertScene(), timeline=tl)
        self.assertTrue(any(h.id == "timeline_storyline" for h in hits))


class TestHeapDeep(unittest.TestCase):
    def test_leak_and_fragmentation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "heap.ass"
            path.write_bytes(SAMPLE_HEAP_ASS)
            report = parse_mem_usage(
                path,
                assert_msg="Error 0x10,No memory, unable to allocate size=1024",
            )
            self.assertTrue(report.ok)
            self.assertTrue(report.leak_suspects)
            self.assertEqual(report.leak_suspects[0]["file"], "demo_leak.c")
            self.assertGreaterEqual(report.leak_suspects[0]["blocks"], 3)
            self.assertIsNotNone(report.fragmentation.get("assert_alloc_size"))
            self.assertEqual(report.fragmentation.get("assert_alloc_size"), 1024)
            # largest free 256 < 1024 → OOM/碎片提示
            self.assertIn("hint", report.fragmentation)
            self.assertTrue(report.fragmentation["hint"])
            hits = apply_rules(AssertScene(assert_msg="unable to allocate size=1024"), mem_usage=report)
            ids = {h.id for h in hits}
            self.assertIn("heap_fragmentation", ids)
            self.assertIn("leak_suspect", ids)


if __name__ == "__main__":
    unittest.main()
