# DumpTrace 更新记录

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

包版本见 `pyproject.toml` / `dumptrace.__version__`。

## [Unreleased]

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
