# -*- coding: utf-8 -*-
"""符号匹配分项检查单元测试。"""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from dumptrace.symbol_match import assess_symbol_match, extract_map_fingerprint, version_token


def _elf32(entry: int = 0x60010000) -> bytes:
    data = bytearray(52)
    data[0:4] = b"\x7fELF"
    data[4] = 1
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHI", data, 16, 2, 40, 1)
    struct.pack_into("<I", data, 24, entry)
    return bytes(data)


class TestSymbolMatch(unittest.TestCase):
    def test_version_token(self) -> None:
        self.assertEqual(
            version_token("FM255V01_160_320_H_16MB_SW_COM_CD1552"), "CD1552"
        )
        self.assertEqual(version_token("DEMO_COM_EX1234"), "EX1234")

    def test_all_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pv = "FM255V01_160_320_H_16MB_SW_COM_CD1552"
            bt = "01-21-2026 14:07:39"
            axf = root / f"UIX8910_{pv}.axf"
            blob = _elf32(0x60010000)
            blob += (
                f"Platform Version: MOCOR_X\nProject Version:{pv}\n"
                f"HW Version:UIS8910FF\n{bt}\nBy RVDS V4.1\n"
            ).encode("ascii")
            axf.write_bytes(blob)
            mp = root / f"UIX8910_{pv}.map"
            mp.write_text(
                "Component: ARM Compiler Tool: armlink [4d35d2]\n"
                "Image Entry point : 0x60010000\n"
                "Total RO  Size (Code + RO Data)              7104908 (6938.39kB)\n"
                "Total ROM Size (Code + RO Data + RW Data)    7135464 (6968.23kB)\n",
                encoding="utf-8",
            )
            report = assess_symbol_match(
                axf=axf, map_path=mp, project_version=pv, build_time=bt
            )
            by_name = {c.name: c for c in report.checks}
            self.assertEqual(by_name["name_token"].status, "match")
            self.assertEqual(by_name["build_time"].status, "match")
            self.assertEqual(by_name["build_id"].status, "match")
            self.assertEqual(by_name["map_checksum"].status, "match")
            self.assertTrue(report.overall)

    def test_build_time_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pv = "DEMO_COM_CD100"
            axf = root / f"{pv}.axf"
            axf.write_bytes(
                _elf32()
                + f"Project Version:{pv}\n01-21-2026 14:07:39\n".encode("ascii")
            )
            report = assess_symbol_match(
                axf=axf,
                project_version=pv,
                build_time="01-01-2020 00:00:00",
            )
            by_name = {c.name: c for c in report.checks}
            self.assertEqual(by_name["build_time"].status, "mismatch")
            self.assertFalse(report.overall)

    def test_map_entry_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pv = "DEMO_COM_CD100"
            axf = root / f"{pv}.axf"
            axf.write_bytes(
                _elf32(0x60010000)
                + f"Project Version:{pv}\n01-21-2026 14:07:39\n".encode("ascii")
            )
            mp = root / f"{pv}.map"
            mp.write_text(
                "Tool: armlink [abcd12]\nImage Entry point : 0x60020000\n"
                "Total RO  Size (Code + RO Data)              1\n"
                "Total ROM Size (Code + RO Data + RW Data)    2\n",
                encoding="utf-8",
            )
            report = assess_symbol_match(
                axf=axf,
                map_path=mp,
                project_version=pv,
                build_time="01-21-2026 14:07:39",
            )
            by_name = {c.name: c for c in report.checks}
            self.assertEqual(by_name["map_checksum"].status, "mismatch")
            fp = extract_map_fingerprint(mp)
            self.assertEqual(fp["entry"], "0x60020000")
            self.assertTrue(fp["digest"])


if __name__ == "__main__":
    unittest.main()
