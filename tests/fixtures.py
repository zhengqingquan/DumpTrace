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
                Queue_Used:       1
                Queue_Available:  499
                Queue_Start:      0x8097ae60
                Queue_End:        0x8097b630
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
Tasks info:
Task_ID    Name            Tcb_Addr        Current_PC  Queue_All   Queue_Avail
0x0        System Timer Th 0x80ed7178  0x8094ea44  0           3            TX_SUSPENDED   2
0x64       RTOS_Manage     0x80963d54  0x8095e496  10          10           TX_QUEUE_SUSP   5
********0x15       T_P_APP         0x8097b654 76
0x4        T_AUDIO         0x8097d38c  0x8095e496  100         5            TX_QUEUE_SUSP   73
0x80a09ba4 audio_helper    0x80a08ba4  0x8095b310  200         200          TX_SLEEP   67
Stack info:
Task_ID    Name            TotalSize  Max_Used   Available  Cur_Ptr    Start      End        
0x0        System Timer Th 2044       792        1924       0x80fac158 0x80fab9d4 0x80fac1cf
0x64       RTOS_Manage     1020       568        756        0x80efbfb0 0x80efbcbc 0x80efc0b7
0x15       T_P_APP         30720      28000      2720       0x8097aae8 0x8097363c 0x8097ae37
0x4        T_AUDIO         4096       800        3296       0x8097d000 0x8097c000 0x8097dfff
0x80a09ba4 audio_helper    2048       400        1648       0x80a09000 0x80a08800 0x80a09000
timer infomation: 
cur_ticks name rem_ticks re_init_ticks Cur_Ptr Next_Ptr Pre_Ptr
154503 GPIO_Shaking_Timer 819 819 0x80e643ac 0x80e64404 0x80e641dc
154503 MMK period timer 3545 8192 0x80eb30c4 0x80e641dc 0x80eb3464
154503 DCAMERA Timer 81920 81920 0x80eb34bc 0x80eb37c4 0x80ebcd44
154503 USB Detect Timer 0 0 0x80ea8814 0x80eae144 0x80e6c4b4
Active Threads' timer infomation:
cur_ticks name rem_ticks re_init_ticks Cur_Int_Ptr Next_Int_Ptr Pre_Int_Ptr
154503 MMK period timer 3545 8192 0x80eb30cc 0x80e6672c 0x80eb0eac
Semaphore infomation:
Name Counter
"""

# 高队列压力片段（单元测试按需使用）
GOLD_QUEUE_PRESSURE = b"""
Current thread info:
                ID:               0x15
                Name:             T_P_APP
                Queue_Name:       Q_P_APP
                Queue_Total:      100
                Queue_Used:       95
                Queue_Available:  5
"""
