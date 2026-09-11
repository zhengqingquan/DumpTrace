# -*- coding: utf-8 -*-
"""P3：LogSave/.lst / mem 窗口 / Fat·NV·iram 测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dumptrace.ass_parser import AssertScene
from dumptrace.log_meta import parse_log_meta
from dumptrace.mem_window import extract_mem_windows
from dumptrace.rules import apply_rules
from dumptrace.sideband import parse_sideband

SAMPLE_LOGSAVE_ASS = b"""
Memory Dumping Finished:begin addr=0x80000000,total size=1024Byte(0x00000400)
=============== Dump LogSave ArmLog Memory==============
no logsave armlog
=============== Dump LogSave DspLog Memory==============
no logsave DspLog
=============== Dump LogSave IQ Memory==============
no logsave IQ
Allocated memory info:
"""

SAMPLE_SIDEBAND_ASS = b"""
h. Print Fat system control block info.
s. Dump Fixed NV  to file.
w. Print iram Information.
Fat system control block information:
fat_status=OK
mount_count=1
free_clusters=100
NV Information:
nv_id=1
nv_len=32
iram Information:
iram_base=0x00000000
iram_size=65536
Mutex Information:
"""

SAMPLE_SIDEBAND_MENU = b"""
h. Print Fat system control block info.
s. Dump Fixed NV  to file.
u. Dump Running NV to file.
w. Print iram Information.
z. Reset MCU.
Current Version:
"""


class TestLogMeta(unittest.TestCase):
    def test_logsave_and_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ass = root / "demo.ass"
            ass.write_bytes(SAMPLE_LOGSAVE_ASS)
            mem = root / "demo_1.mem"
            mem.write_bytes(b"\x00" * 512)  # mismatch vs 1024
            lst = root / "demo.lst"
            lst.write_text("Tool=Logel\nVersion=1.2.3\n", encoding="utf-8")
            report = parse_log_meta(
                ass_path=ass,
                armlog_dir=root,
                lst_path=lst,
                package_files=[
                    type("E", (), {"role": "ass", "path": ass})(),
                    type("E", (), {"role": "mem", "path": mem})(),
                ],
            )
            self.assertTrue(report.ok)
            self.assertEqual(len(report.logsave), 3)
            self.assertTrue(all(c.empty for c in report.logsave if c.present))
            self.assertIsNotNone(report.lst)
            self.assertEqual(report.lst.fields.get("Tool"), "Logel")
            self.assertIn("mem:size_mismatch", report.integrity.get("gaps") or [])
            hits = apply_rules(AssertScene(), log_meta=report)
            ids = {h.id for h in hits}
            self.assertIn("logsave_empty", ids)
            self.assertIn("capture_incomplete", ids)
            self.assertIn("lst_meta_present", ids)


class TestMemWindow(unittest.TestCase):
    def test_window_around_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mem = Path(td) / "demo.mem"
            # base 0x80000000, put pattern at offset 0x100
            data = bytearray(0x200)
            for i in range(16):
                data[0x100 + i] = i
            mem.write_bytes(data)
            report = extract_mem_windows(
                mem,
                fault_addr="0x80000100",
                regs={"R0": "0x80000108", "R1": "0x00000004"},
                mem_base="0x80000000",
                window_bytes=64,
            )
            self.assertTrue(report.ok)
            fault = next(w for w in report.windows if w.role == "fault")
            self.assertTrue(fault.ok)
            self.assertIn(0x00, fault.data)  # center region contains pattern
            hits = apply_rules(
                AssertScene(fault_addr="0x80000100"), mem_window=report
            )
            self.assertTrue(any(h.id == "mem_window_extracted" for h in hits))

    def test_fault_unmapped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mem = Path(td) / "demo.mem"
            mem.write_bytes(b"\x00" * 64)
            report = extract_mem_windows(
                mem,
                fault_addr="0x00000004",
                mem_base="0x80000000",
                window_bytes=32,
            )
            self.assertFalse(report.ok)
            hits = apply_rules(
                AssertScene(fault_addr="0x00000004"), mem_window=report
            )
            self.assertTrue(any(h.id == "fault_addr_unmapped" for h in hits))

    def test_no_fault_uses_high_regs_and_sp(self) -> None:
        """无 Fault 且 R0–R3 为空时，仍应用 R4/SP 开窗（勿误 skip）。"""
        with tempfile.TemporaryDirectory() as td:
            mem = Path(td) / "demo.mem"
            data = bytearray(0x300)
            data[0x200] = 0xAB
            mem.write_bytes(data)
            report = extract_mem_windows(
                mem,
                fault_addr=None,
                regs={
                    "R0": "0x0",
                    "R1": "0x0",
                    "R2": "0x1",
                    "R3": "0x1",
                    "R4": "0x80000200",
                    "SP": "0x80000100",
                    "PC": "0x606513d4",
                    "LR": "0x603d1165",
                },
                mem_base="0x80000000",
                window_bytes=32,
            )
            self.assertTrue(report.ok)
            self.assertFalse(report.skipped)
            roles = {w.role for w in report.windows if w.ok}
            self.assertIn("r4", roles)
            self.assertIn("sp", roles)
            self.assertNotIn("pc", roles)  # 代码区，不在 .mem
            r4 = next(w for w in report.windows if w.role == "r4")
            # center 在窗口中部，不是 data[0]
            center_off = r4.center - (r4.mem_base + r4.file_offset)
            self.assertEqual(r4.data[center_off], 0xAB)


class TestSideband(unittest.TestCase):
    def test_parse_sections(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sb.ass"
            path.write_bytes(SAMPLE_SIDEBAND_ASS)
            report = parse_sideband(path)
            self.assertTrue(report.ok)
            self.assertFalse(report.skipped)
            kinds = {s.kind for s in report.sections if s.present}
            self.assertIn("fat", kinds)
            self.assertIn("nv", kinds)
            self.assertIn("iram", kinds)
            hits = apply_rules(AssertScene(), sideband=report)
            self.assertTrue(any(h.id == "sideband_present" for h in hits))

    def test_skip_menu_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "menu.ass"
            path.write_bytes(SAMPLE_SIDEBAND_MENU)
            report = parse_sideband(path)
            self.assertTrue(report.skipped)
            self.assertFalse(report.ok)


if __name__ == "__main__":
    unittest.main()
