# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path

from dumptrace.config import load_config, parse_simple_toml


TOML = """
[tools]
addr2line = "D:/tools/addr2line.exe"

[export]
copy_ass = true
bundle = true

[credibility]
warn_lost_pct = 3.5
bad_lost_pct = 12

[timeline]
keywords = ["camera", "abort"]
"""


class TestConfig(unittest.TestCase):
    def test_parse(self) -> None:
        data = parse_simple_toml(TOML)
        self.assertEqual(data["tools"]["addr2line"], "D:/tools/addr2line.exe")
        self.assertTrue(data["export"]["copy_ass"])
        self.assertEqual(data["credibility"]["warn_lost_pct"], 3.5)
        self.assertEqual(data["timeline"]["keywords"], ["camera", "abort"])

    def test_load_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "dumptrace.toml"
            p.write_text(TOML, encoding="utf-8")
            cfg = load_config(p)
            self.assertEqual(cfg.addr2line, Path("D:/tools/addr2line.exe"))
            self.assertTrue(cfg.copy_ass)
            self.assertTrue(cfg.bundle)
            self.assertEqual(cfg.warn_lost_pct, 3.5)
            self.assertEqual(cfg.timeline_keywords, ["camera", "abort"])


if __name__ == "__main__":
    unittest.main()
