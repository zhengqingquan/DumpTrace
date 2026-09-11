# -*- coding: utf-8 -*-
"""ASS 解析单元测试（内嵌金样本片段）。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dumptrace.ass_parser import parse_ass
from dumptrace.rules import apply_rules
from tests.fixtures import GOLD_ASS_BLOB


class TestAssParser(unittest.TestCase):
    def test_gold_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.ass"
            path.write_bytes(GOLD_ASS_BLOB)
            scene = parse_ass(path)

        self.assertEqual(scene.assert_msg, "Abort exception handler !")
        self.assertEqual(scene.exception_addr, "0x60127474")
        self.assertEqual(scene.fault_addr, "0x4")
        self.assertEqual(scene.thread_name, "T_P_APP")
        self.assertEqual(scene.queue_name, "Q_P_APP")
        self.assertEqual(scene.regs.get("PC"), "0x60022f48")
        self.assertEqual(scene.regs.get("R0"), "0x0")
        self.assertIn("EX1234", scene.project_version or "")
        self.assertTrue(scene.mode_regs.get("SVC", {}).get("R14"))

        hits = apply_rules(scene)
        ids = {h.id for h in hits}
        self.assertIn("null_deref", ids)
        self.assertIn("data_abort", ids)
        self.assertIn("thread_hint", ids)


if __name__ == "__main__":
    unittest.main()
