# DumpTrace 更新记录

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

包版本见 `pyproject.toml` / `dumptrace.__version__`。

## [Unreleased]

### 新增

- P0：从 `.ass` 解析全任务表（`Tasks info` + `Stack info`）、定时器列表（含 Active Threads）、队列水位；导出 `tasks.txt` / `tasks.json` / `timers.txt`，`scene.md` 摘要可疑线程与定时器模块分布。
- 规则：`queue_pressure`、`stack_near_overflow`、`assert_thread_not_running`、`task_blocked`、`periodic_timer_active`；配置项 `[rtos]` / `[timer_modules]`。
- P1：Mutex/Semaphore/Event（`sync_objects.*`）、专用内存池（扩展 `mem_usage` pools）、MMI 句柄树（`mmi_state`）；规则 `lock_held_by_X` / `waiters_gt_0` / `dedicated_pool_pressure`。
- 符号匹配分项检查：`name_token`（文件名片段）、`build_time`（编译时间）、`build_id`（Project Version）、`map_checksum`（同 stem `.map` 入口点 + 摘要指纹）；CLI / `scene.md` 分别提示，overall 写入 `axf_match`。
- 从 `.ass` 解析内存使用：System/Static 池 Total/Avail/Used、空间段 ALLOC/FREE、Allocated memory info Top；导出 `mem_usage.txt` / `mem_usage.json`，并增加 `oom_assert` / `mem_pressure` 规则。
- 文档：[能力规划](docs/能力规划.md)（后续可从日志解析项的优先级与验收建议；平台通用，不绑定具体业务）。

## [0.1.0] - 2026-09-11

### 新增

- 单包分析流水线：接入 armlog、解析 ASS、符号反查、规则判读、导出现场（`scene.md` / `scene.json`）。
- 可信度评估（`log_stat`）、批量分析与双 dump 对比。
- 可选 Logel 时间线与 MEM 栈/候选调用栈（依赖 [logel2txt](https://github.com/zhengqingquan/logel2txt) 与 `addr2line`）。
- CLI 子命令：`analyze` / `batch` / `diff` / `version`；支持 `dumptrace.toml` 与 `--skip-timeline` / `--skip-mem`。
- PyInstaller 打包：`requirements.txt`、`dumptrace.spec` → `dist/dumptrace.exe`。

### 变更

- 对外版本号整理为 **0.1.0**。
- 文档与示例脱敏：去掉本机绝对路径与真实工程标识；时间线发现改为同级目录 / `DUMPTRACE_LOGEL2TXT`。
- `logel2txt` 依赖说明统一指向 <https://github.com/zhengqingquan/logel2txt>。
- README 与功能清单去掉分期表述，按能力重排；输出文件说明补全。
