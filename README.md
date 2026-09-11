# DumpTrace

从展锐 Logel `*_armlog` 死机包反查：异常画像 → 符号定位 → 时间线 / 栈深挖 → 导出现场。

与 [logel2txt](https://github.com/zhengqingquan/logel2txt) **上下游**：时间线复用其 Trace 导出，不重复实现解码。

版本：**0.1.0** · 详见 [CHANGELOG](CHANGELOG.md)

## 功能

| 能力 | 说明 |
|------|------|
| 死机包接入 | 识别 `*_armlog` / `dump_*`，配对 `.axf`/`.map`，缺 ASS 中止、缺 AXF 降级 |
| ASS 异常画像 | Assert / Fault / 线程 / 寄存器 / 版本等 |
| 符号匹配 | 文件名片段 / 编译时间 / Build ID / map 入口与摘要指纹，分项提示 |
| 符号反查 | PC / LR / Exception → 函数、文件、行（`addr2line`） |
| 规则判读 | 空指针偏移、Abort 类型、线程名、OOM/内存压力启发式与置信度 |
| 内存使用 | ASS 池 Total/Avail/Used、段 ALLOC/FREE、分配表 Top（`mem_usage.*`） |
| Log 可信度 | 读 `*_log_stat.txt`，报告中标注丢包可信度 |
| 时间线 | 死机前关键字事件（复用 logel2txt） |
| MEM 栈深挖 | 栈区切片、疑似返回地址 → 候选调用栈 |
| 现场导出 | `scene.md` / `scene.json`，可选 zip / 证据拷贝 |
| 批量分析 | 父目录多 dump → `summary.csv` |
| 现场对比 | 双 dump → `diff.json` / `diff.md` |
| 配置 | `dumptrace.toml`（工具路径、导出、阈值、关键字等） |

不在范围内：自动修根因 / 补丁、替代 Logel 完整解码、GUI。

## 文档

- [反查技术路径](docs/反查技术路径.md)
- [功能清单](docs/功能清单.md)

## 快速开始

```bat
cd /d <REPO_ROOT>
python dumptrace.py analyze "D:\path\to\dump_xxx" --out out --bundle
python dumptrace.py batch "D:\path\to\parent" --out out\batch
python dumptrace.py diff dump_a dump_b --out out\diff.json
python dumptrace.py analyze dump_xxx --skip-timeline --skip-mem
```

依赖：

- 时间线：[logel2txt](https://github.com/zhengqingquan/logel2txt)（同级目录、`PYTHONPATH` 或 `DUMPTRACE_LOGEL2TXT`）
- 符号：`addr2line`（或 `DUMPTRACE_ADDR2LINE` / `--addr2line`）

## 输出

### `analyze` → `out/<dump_id>_scene/`

| 文件 | 作用 |
|------|------|
| `scene.md` | 人类可读一页纸报告（结论、线程/Fault、符号、规则、可信度、警告） |
| `scene.json` | 结构化全量现场（供流水线 / `diff` 复用） |
| `assert_excerpt.txt` | 从 `.ass` 抽出的关键断言/异常原文摘录 |
| `symbols.txt` | 地址反查表（role / addr / func / file:line） |
| `manifest.json` | 源包文件清单、路径、大小、哈希前缀与工具版本（归档用） |
| `timeline.txt` | 死机前关键字时间线（未 `--skip-timeline` 且时间线可用时） |
| `stack.bin` | 线程栈区原始二进制切片（未 `--skip-mem` 且有 `.mem` 时） |
| `stack.hex` | 同上内容的十六进制可读视图 |
| `stack_error.txt` | 栈提取失败时的原因说明（替代 stack.bin/hex） |
| `callstack_candidates.txt` | 栈上疑似返回地址及符号候选（未 `--skip-mem` 时） |
| `mem_usage.txt` / `mem_usage.json` | ASS 内存池/段/分配表使用摘要 |
| `evidence/` | 可选证据目录：`--copy-ass` 拷 `.ass`；`--full` 再拷 mem/logel 等 |
| `../<dump_id>_scene.zip` | `--bundle` 时打在 scene 目录**同级**的现场包 |

### `batch` → `--out` 目录

| 文件 | 作用 |
|------|------|
| `summary.csv` | 各 dump 一行汇总（线程、Fault、PC、规则、是否成功等） |
| `<dump_id>_scene/` | 每个输入各一份上述 analyze 现场目录 |

### `diff` → `--out`（默认 `out/diff.json`）

| 文件 | 作用 |
|------|------|
| `diff.json` | 双 dump / 双现场差异的结构化结果 |
| `diff.md` | 同上差异的 Markdown 说明（与 json 同名旁路生成） |

## 开发与打包

```bat
python -m unittest discover -s tests -v
pip install -r requirements.txt
pyinstaller dumptrace.spec
```

产物：`dist/dumptrace.exe`（默认不内嵌 logel2txt）。
