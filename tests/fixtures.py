# -*- coding: utf-8 -*-
# 演示用金样本（工程/平台标识为假数据，结构对齐真实 ASS）
GOLD_ASS_BLOB = b"""
Current Version: 
Platform Version: MOCOR_20B.CHIP_DEMO_W24.08.4_Debug
Project Version:DEMO_V01_160_320_H_16MB_SW_COM_EX1234
BASE  Version:     BASE_SVN
HW Version:CHIP_DEMO_FF
10-10-2025 14:17:03
By RVDS V4.1
rvosmem.c(384)
Exception at 0x60127474
ASSERT(Abort exception handler !)
Abort fault(DFSR:0x0000080f): Permission fault, Domain valid !
Fault address :0x00000004
Current thread info:
                ID:               0x15
                Name:             T_P_APP
                Tcb_Addr:         0x8097b654
                Last_Err:         0x0
                Stack_Start:      0x8097363c
                Stack_End:        0x8097ae37
                Queue_Name:       Q_P_APP
                Queue_Total:      500
Memory Dumping Finished:begin addr=0x80000000,total size=29431680Byte(0x01c11780)
Current status is exception, below is the registers before Exception:
 > Current mode:
        R0  = 0x00000000    R1   = 0x8097abc4
        R2  = 0x0000003f    R3   = 0x60000093
        R4  = 0x8097abcc    R5   = 0x8097abc0
        R6  = 0x8097ac20    R7   = 0x00000000
        R8  = 0x00000001    R9   = 0x00000000
        R10 = 0x80eca08c    R11  = 0x8097ab28
        R12 = 0x20021202    R13  = 0x80fab9a8
        R14 = 0x60127474    PC   = 0x60022f48
        SPSR= 0x80000033    CPSR = 0x40000197
 > SVC mode:
        R13 = 0x8097aae8    R14  = 0x8095e859
        SPSR = 0x20000033
 > IRQ mode:
        R13 = 0x80faafa8    R14  = 0x603457e1
Assert Debug Menu:
 > 1. Print assert info.
"""
