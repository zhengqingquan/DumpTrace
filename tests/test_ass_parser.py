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

    def test_bracketed_thread_and_queue_names(self) -> None:
        blob = b"""
Exception at 0x60394156
ASSERT(Abort exception handler !)
Abort fault(DFSR:0x00000005): Translation fault, Domain invalid !
Fault address :0x4075b166
Current thread info:
                ID:               0x809aba24
                Name:             [P_receive Mqtt]
                Tcb_Addr:         0x809aaa24
                Last_Err:         0x0
                Stack_Start:      0x809aabc8
                Stack_End:        0x809aebc3
                Queue_Name:       [Q_receive Mqtt]
                Queue_Total:      32
                Queue_Used:       0
                Queue_Available:  32
Current status is exception, below is the registers before Exception:
 > Current mode:
        R0  = 0x4075b142    R1   = 0x809f08c8
        R14 = 0x60394156    PC   = 0x60013c74
"""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mqtt.ass"
            path.write_bytes(blob)
            scene = parse_ass(path)
        self.assertEqual(scene.thread_name, "[P_receive Mqtt]")
        self.assertEqual(scene.queue_name, "[Q_receive Mqtt]")
        self.assertEqual(scene.thread_id, "0x809aba24")


if __name__ == "__main__":
    unittest.main()
