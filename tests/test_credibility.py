# -*- coding: utf-8 -*-
import unittest

from dumptrace.credibility import assess_credibility


class TestCredibility(unittest.TestCase):
    def test_high(self) -> None:
        c = assess_credibility({"Total lost": "1.2", "PS MTA lost": "1.0", "Total lost count": "10", "Total package": "1000"})
        self.assertEqual(c.level, "high")

    def test_medium(self) -> None:
        c = assess_credibility({"Total lost": "8.12", "PS MTA lost": "8.11"})
        self.assertEqual(c.level, "medium")

    def test_low(self) -> None:
        c = assess_credibility({"Total lost": "20", "PS MTA lost": "18"})
        self.assertEqual(c.level, "low")

    def test_unknown(self) -> None:
        c = assess_credibility(None)
        self.assertEqual(c.level, "unknown")


if __name__ == "__main__":
    unittest.main()
