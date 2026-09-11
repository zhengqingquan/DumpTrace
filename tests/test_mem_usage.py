# -*- coding: utf-8 -*-
"""内存使用解析单元测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dumptrace.mem_usage import parse_mem_usage
from dumptrace.rules import apply_rules
from dumptrace.ass_parser import AssertScene


SAMPLE_ASS = b"""
Allocated memory info:
No.      Size     FileName (Line)
1        100      demo_a.c (Line 10),addr:80a70000
2        200      demo_b.c (Line 20),addr:80a70100
3        50       demo_a.c (Line 11),addr:80a70200
================== System Space Information ==============
 Begin Address   End Address    Total_Num   Avail_Num   Max_Used   Threshold
 0x80ae1cf4      0x80e65cf4     1000000      100000      900000      65536
 --------------------------------------------------------------
 Start_Addr   End_Addr       Size        State      File_Name(Line)
 0x80ae1cf4   0x80ae5d18     16420  ALLOC        sleep_phy.c(1056)
 0x80ae5d18   0x80af1d3c     49188  ALLOC        sci_mem.c(405)
 0x80af1d3c   0x80af7d3c     24576  FREE         (0)
================== Static Space Information ==============
 Begin Address   End Address    Total_Num   Avail_Num   Max_Used   Threshold
 0x80a7dcf4      0x80ae1cf4     200000       20000       180000      81920
 --------------------------------------------------------------
 Start_Addr   End_Addr       Size        State      File_Name(Line)
 0x80a7dcf4   0x80a7de3c     328  ALLOC        threadx_os.c(1486)
 0x80a7de3c   0x80a7ee3c     4096 FREE         (0)
================== Base Space Information ==============
------------Base Space Base Segment--------------------
---Base Addr:0x80e65d38, End Addr:0x80e724e0, Length:51112, Type:Base----
Start_Addr   End_Addr       Size        State      File_Name(Line)
 0x80e65f18   0x80e699a8     14992
ALLOC
efs_item.c(1889)
 0x80e699a8   0x80e69c38     656
FREE
"""


class TestMemUsage(unittest.TestCase):
    def test_parse_pools_and_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.ass"
            path.write_bytes(SAMPLE_ASS)
            report = parse_mem_usage(path)
            self.assertTrue(report.ok)
            self.assertEqual(len(report.pools), 2)
            names = {p.name for p in report.pools}
            self.assertIn("System Space Information", names)
            self.assertIn("Static Space Information", names)
            sys_p = next(p for p in report.pools if "System" in p.name)
            self.assertEqual(sys_p.total, 1000000)
            self.assertEqual(sys_p.avail, 100000)
            self.assertEqual(sys_p.used, 900000)
            self.assertAlmostEqual(sys_p.used_pct or 0, 90.0)
            self.assertEqual(report.overall.get("total"), 1200000)
            self.assertEqual(report.overall.get("avail"), 120000)
            self.assertGreaterEqual(len(report.segments), 1)
            base = report.segments[0]
            self.assertGreater(base.alloc_bytes, 0)
            self.assertGreater(base.free_bytes, 0)
            ai = report.allocated_info
            self.assertEqual(ai.get("count"), 3)
            self.assertEqual(ai.get("total_bytes"), 350)
            top = {f["file"]: f for f in ai.get("top_files") or []}
            self.assertEqual(top["demo_a.c"]["bytes"], 150)
            self.assertTrue(report.largest_free_blocks)

    def test_rules_mem_pressure_and_oom(self) -> None:
        scene = AssertScene(
            assert_msg="Error 0x10,No memory, unable to allocate,demo.c, line=1"
        )
        hits = apply_rules(
            scene,
            mem_usage={
                "overall": {
                    "used": 95,
                    "total": 100,
                    "avail": 5,
                    "used_pct": 95.0,
                }
            },
        )
        ids = {h.id for h in hits}
        self.assertIn("oom_assert", ids)
        self.assertIn("mem_pressure", ids)


if __name__ == "__main__":
    unittest.main()
