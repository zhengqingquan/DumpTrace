# -*- coding: utf-8 -*-
"""ingest / 导出现场冒烟测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dumptrace.pipeline import analyze
from tests.fixtures import GOLD_ASS_BLOB


class TestPipelineSmoke(unittest.TestCase):
    def test_export_without_axf(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            armlog = root / "2025_10_10_14_19_49_380_armlog"
            armlog.mkdir()
            ass = armlog / "2025_10_10_14_19_49_380.ass"
            ass.write_bytes(GOLD_ASS_BLOB)
            out = root / "out"
            result = analyze(
                root, out_dir=out, export=True, bundle=True, skip_timeline=True, skip_mem=True
            )
            self.assertTrue(result.ok)
            self.assertEqual(result.exit_code, 0)
            scene_dir = Path(result.export["out_dir"])
            self.assertTrue((scene_dir / "scene.json").is_file())
            self.assertTrue((scene_dir / "scene.md").is_file())
            self.assertTrue((scene_dir / "assert_excerpt.txt").is_file())
            data = json.loads((scene_dir / "scene.json").read_text(encoding="utf-8"))
            self.assertEqual(data["assert"]["thread_name"], "T_P_APP")
            self.assertEqual(data["assert"]["fault_addr"], "0x4")
            self.assertTrue(result.export.get("bundle"))


if __name__ == "__main__":
    unittest.main()
