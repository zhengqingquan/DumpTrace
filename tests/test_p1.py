# -*- coding: utf-8 -*-
"""金样本字段快照回归（不依赖巨型 mem/axf）。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dumptrace.pipeline import analyze
from tests.fixtures import GOLD_ASS_BLOB

# 稳定字段快照：防止解析回退
GOLD_SNAPSHOT = {
    "assert_msg": "Abort exception handler !",
    "exception_addr": "0x60127474",
    "fault_addr": "0x4",
    "thread_name": "T_P_APP",
    "queue_name": "Q_P_APP",
    "pc": "0x60022f48",
    "r0": "0x0",
    "project_token": "EX1234",
    "rule_ids": ["null_deref", "data_abort", "thread_hint", "r0_null"],
}


class TestGoldSnapshot(unittest.TestCase):
    def test_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            armlog = root / "2025_10_10_14_19_49_380_armlog"
            armlog.mkdir()
            (armlog / "2025_10_10_14_19_49_380.ass").write_bytes(GOLD_ASS_BLOB)
            (armlog / "2025_10_10_14_19_49_380_log_stat.txt").write_text(
                "Total lost=8.12\nPS MTA lost=8.11\nTotal lost count=857\nTotal package=9696\n",
                encoding="utf-8",
            )
            result = analyze(
                root,
                out_dir=root / "out",
                export=True,
                skip_timeline=True,
                skip_mem=True,
            )
            self.assertTrue(result.ok)
            scene = result.scene
            self.assertEqual(scene.assert_msg, GOLD_SNAPSHOT["assert_msg"])
            self.assertEqual(scene.exception_addr, GOLD_SNAPSHOT["exception_addr"])
            self.assertEqual(scene.fault_addr, GOLD_SNAPSHOT["fault_addr"])
            self.assertEqual(scene.thread_name, GOLD_SNAPSHOT["thread_name"])
            self.assertEqual(scene.queue_name, GOLD_SNAPSHOT["queue_name"])
            self.assertEqual(scene.regs.get("PC"), GOLD_SNAPSHOT["pc"])
            self.assertEqual(scene.regs.get("R0"), GOLD_SNAPSHOT["r0"])
            self.assertIn(GOLD_SNAPSHOT["project_token"], scene.project_version or "")
            ids = [r.id for r in result.rules]
            for rid in GOLD_SNAPSHOT["rule_ids"]:
                self.assertIn(rid, ids)
            self.assertIsNotNone(result.credibility)
            self.assertEqual(result.credibility.level, "medium")

            data = json.loads(
                (Path(result.export["out_dir"]) / "scene.json").read_text(encoding="utf-8")
            )
            self.assertEqual(data["credibility"]["level"], "medium")
            self.assertIn("抓 log 可信度", (Path(result.export["out_dir"]) / "scene.md").read_text(encoding="utf-8"))


class TestBatch(unittest.TestCase):
    def test_batch_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ("dump_a", "dump_b"):
                arm = root / name / f"{name}_armlog"
                arm.mkdir(parents=True)
                (arm / f"{name}.ass").write_bytes(GOLD_ASS_BLOB)
            from dumptrace.batch import run_batch
            from dumptrace.config import DumpTraceConfig

            cfg = DumpTraceConfig(enable_timeline=False, enable_mem=False)
            summary = run_batch(root, out_dir=root / "batch_out", config=cfg)
            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["ok"], 2)
            csv_path = Path(summary["summary_csv"])
            self.assertTrue(csv_path.is_file())
            text = csv_path.read_text(encoding="utf-8-sig")
            self.assertIn("dump_id", text)
            self.assertIn("T_P_APP", text)


if __name__ == "__main__":
    unittest.main()
