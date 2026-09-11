# -*- coding: utf-8 -*-
"""P0：任务表 / 定时器 / 队列解析测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dumptrace.ass_parser import parse_ass
from dumptrace.rules import apply_rules
from dumptrace.rtos_info import parse_rtos_info
from tests.fixtures import GOLD_ASS_BLOB, GOLD_QUEUE_PRESSURE


class TestRtosInfo(unittest.TestCase):
    def test_parse_tasks_timers_queues(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "demo.ass"
            path.write_bytes(GOLD_ASS_BLOB)
            report = parse_rtos_info(
                path, assert_thread_name="T_P_APP", assert_thread_id="0x15"
            )
            self.assertTrue(report.ok)
            self.assertGreaterEqual(len(report.tasks), 4)
            names = {t.name for t in report.tasks}
            self.assertIn("T_P_APP", names)
            self.assertIn("T_AUDIO", names)
            cur = next(t for t in report.tasks if t.name == "T_P_APP")
            self.assertTrue(cur.is_current)
            self.assertEqual(cur.priority, 76)
            audio = next(t for t in report.tasks if t.name == "T_AUDIO")
            self.assertEqual(audio.queue_all, 100)
            self.assertEqual(audio.queue_avail, 5)
            self.assertEqual(audio.queue_used, 95)
            self.assertAlmostEqual(audio.queue_used_pct or 0, 95.0)
            self.assertIsNotNone(audio.stack_total)
            self.assertGreaterEqual(audio.stack_used_pct or 0, 0)

            self.assertGreaterEqual(len(report.timers), 3)
            periodic = [t for t in report.timers if t.periodic]
            self.assertGreaterEqual(len(periodic), 2)
            mods = report.timer_module_counts
            self.assertTrue(mods.get("display") or mods.get("camera") or mods.get("usb"))

            self.assertTrue(any(q.source == "current_thread" for q in report.queues))
            sus_names = {s["name"] for s in report.suspicious_tasks}
            self.assertIn("T_P_APP", sus_names)
            self.assertIn("T_AUDIO", sus_names)  # queue high

    def test_rules_queue_stack_timer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "demo.ass"
            path.write_bytes(GOLD_ASS_BLOB)
            scene = parse_ass(path)
            self.assertEqual(scene.queue_total, 500)
            self.assertEqual(scene.queue_used, 1)
            report = parse_rtos_info(
                path, assert_thread_name=scene.thread_name, assert_thread_id=scene.thread_id
            )
            hits = apply_rules(scene, rtos_info=report, queue_pressure_pct=80.0)
            ids = {h.id for h in hits}
            self.assertIn("queue_pressure", ids)  # T_AUDIO 95%
            self.assertIn("stack_near_overflow", ids)  # T_P_APP ~91%
            self.assertIn("periodic_timer_active", ids)

    def test_current_queue_pressure_without_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "q.ass"
            path.write_bytes(GOLD_QUEUE_PRESSURE)
            scene = parse_ass(path)
            hits = apply_rules(scene, rtos_info=None, queue_pressure_pct=80.0)
            # scene 自身队列字段即可触发
            self.assertTrue(any(h.id == "queue_pressure" for h in hits))


if __name__ == "__main__":
    unittest.main()
