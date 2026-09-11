# -*- coding: utf-8 -*-
"""P1：同步原语 / 专用池 / MMI 解析测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dumptrace.ass_parser import AssertScene
from dumptrace.mem_usage import parse_mem_usage
from dumptrace.mmi_state import parse_mmi_state
from dumptrace.rules import apply_rules
from dumptrace.sync_objects import parse_sync_objects

SAMPLE_P1_ASS = b"""
Current thread info:
                ID:               0x15
                Name:             T_P_APP
Event Information:
Name                CurrentFlag TotalSuspended SuspendList
NULL                0           1
                                               T_CM
SCM_IRP             80000000    1
                                               SCM_TASK
FAT_TaskTrig        0           3
                                               T_FFS
                                               E
                                               D
FREQ_CHNG_EVENT     1f          0
Mutex Information:
Name                          Owner               TotalSuspended OwnershipCount SuspendList
CLOCK MUTEX                   [No Owner]          0              0
CHIP_CLK_MUTEX                T_P_APP             0              1
rpc_lock                      T_P_APP             1              1
                                               T_AUDIO
COMDEDUG_MUTEX                T_P_ATC             0              0
Semaphore infomation:
Name                                Counter
hisr0x51                               0
Suspend Task_Name :  hisr0
LCD TASK SEMAPHORE                     0
Suspend Task_Name :  T_LCD
USB VBUS semaphore                     1
========================================================
s_handle_list
(MMI_APPLET_NODE_T*)0x80eaddfc,handle=0x00ff0000,parent_tree_handle=0x00000000,parent_handle=0x00000000,id=0x00008001,name=DEMO_IDLE_APPLET_ID
(MMI_WINDOW_NODE_T*)0x80eae434,handle=0x01010001,parent_tree_handle=0x00000000,parent_handle=0x00ff0000,id=0x00280001,name=UNKNOWN
(MMI_CTRL_NODE_T*)0x80eb4fdc,handle=0x01020002,parent_tree_handle=0x00000000,parent_handle=0x01010001,id=0x00280003,name=DEMO_GUI_ANIM_ID
s_zorder_system
(MMI_WINDOW_NODE_T*)0x80eae434,handle=0x01010001,parent_tree_handle=0x00000000,parent_handle=0x00ff0000,id=0x00280001,name=UNKNOWN
s_layer_arr
block_id=0,is_bltlayer=1,size=102400,name=ui_layer.c,line=2162
data.image 0x80e22b00 320. 160. /RGB565LE
BT:state=0,timer=0
================== System Space Information ==============
 Begin Address   End Address    Total_Num   Avail_Num   Max_Used   Threshold
 0x80ae1cf4      0x80e65cf4     1000000      100000      900000      65536
================== vector font cache Information ==============
 Begin Address   End Address    Total_Num   Avail_Num   Max_Used
 0x80f0564c      0x80f1564c     65536        1000        64536
================== MMIPB_POOL Information ==============
 Begin Address   End Address    Total_Num   Avail_Num   Max_Used
 0x80997714      0x809a3f14     51200        51192       51201
"""


class TestSyncObjects(unittest.TestCase):
    def test_parse_mutex_sem_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p1.ass"
            path.write_bytes(SAMPLE_P1_ASS)
            report = parse_sync_objects(path)
            self.assertTrue(report.ok)
            self.assertGreaterEqual(len(report.mutexes), 3)
            chip = next(m for m in report.mutexes if m.name == "CHIP_CLK_MUTEX")
            self.assertEqual(chip.owner, "T_P_APP")
            self.assertGreaterEqual(len(report.held_locks), 2)
            self.assertGreaterEqual(len(report.semaphores), 2)
            lcd = next(s for s in report.semaphores if "LCD TASK" in s.name)
            self.assertIn("T_LCD", lcd.waiters)
            self.assertGreaterEqual(len(report.events), 3)
            fat = next(e for e in report.events if e.name == "FAT_TaskTrig")
            self.assertEqual(fat.total_suspended, 3)
            self.assertIn("T_FFS", fat.waiters)
            self.assertTrue(report.waited)

    def test_rules_lock_and_waiters(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p1.ass"
            path.write_bytes(SAMPLE_P1_ASS)
            sync = parse_sync_objects(path)
            scene = AssertScene(thread_name="T_P_APP")
            hits = apply_rules(scene, sync_objects=sync)
            ids = {h.id for h in hits}
            self.assertIn("lock_held_by_X", ids)
            self.assertIn("waiters_gt_0", ids)


class TestDedicatedPools(unittest.TestCase):
    def test_dedicated_pools_and_rule(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p1.ass"
            path.write_bytes(SAMPLE_P1_ASS)
            mem = parse_mem_usage(path)
            self.assertTrue(mem.ok)
            kinds = {p.kind for p in mem.pools}
            self.assertIn("main", kinds)
            self.assertIn("dedicated", kinds)
            names = {p.name for p in mem.pools}
            self.assertTrue(any("font cache" in n for n in names))
            self.assertTrue(any("MMIPB" in n for n in names))
            # overall 仍按主池
            self.assertEqual(mem.overall.get("pool_count"), 1)
            self.assertGreaterEqual(mem.overall.get("dedicated_pool_count") or 0, 2)
            font = next(p for p in mem.pools if "font cache" in p.name)
            self.assertGreaterEqual(font.used_pct or 0, 90)
            hits = apply_rules(AssertScene(), mem_usage=mem)
            self.assertTrue(any(h.id == "dedicated_pool_pressure" for h in hits))


class TestMmiState(unittest.TestCase):
    def test_parse_mmi(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p1.ass"
            path.write_bytes(SAMPLE_P1_ASS)
            report = parse_mmi_state(path)
            self.assertTrue(report.ok)
            self.assertEqual(report.current_applet.get("name"), "DEMO_IDLE_APPLET_ID")
            self.assertIsNotNone(report.focus_window)
            self.assertEqual(len(report.anim_controls), 1)
            self.assertEqual(report.anim_controls[0]["name"], "DEMO_GUI_ANIM_ID")
            self.assertGreaterEqual(len(report.layers), 1)
            hits = apply_rules(AssertScene(), mmi_state=report)
            self.assertTrue(any(h.id == "mmi_state_present" for h in hits))


if __name__ == "__main__":
    unittest.main()
