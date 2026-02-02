# 本地 Kernel Crash Dump 分析器

## 概述

`local_analyzer.py` 是 ke-analyzer 系统的本地分析模块，支持直接从本地目录分析 kernel crash dump，无需从 Jira 下载。

## 功能特性

- **本地分析**: 直接读取本地 crash dump 目录
- **自动解析**: 自动解析 `__exp_main.txt`, `SYS_REBOOT_REASON`, `SYS_KERNEL_LOG` 等文件
- **调用栈解析**: 提取并格式化调用栈信息
- **根因分析**: 根据崩溃类型自动生成根因分析
- **修复建议**: 根据崩溃特征生成修复建议
- **Markdown 报告**: 生成结构化的 Markdown 分析报告

## 使用方法

### 命令行使用

```bash
# 分析默认的两个 crash dump 目录
python3 local_analyzer.py

# 分析指定目录
python3 -c "
import asyncio
from local_analyzer import analyze_crash_dump

async def main():
    analysis, report_path = await analyze_crash_dump(
        '/path/to/crash/dump',
        '/path/to/output'
    )
    print(f'Report saved to: {report_path}')

asyncio.run(main())
"
```

### 作为模块使用

```python
from local_analyzer import LocalCrashDumpAnalyzer, AnalysisReportGenerator

# 创建分析器
analyzer = LocalCrashDumpAnalyzer('/path/to/crash/dump')

# 执行分析
analysis = analyzer.analyze()

# 生成报告
generator = AnalysisReportGenerator(analysis)
report = generator.generate_markdown()

# 保存报告
generator.save_report('/path/to/output/report.md')
```

## 支持的文件

分析器会自动读取以下文件：

- `__exp_main.txt` - 异常主要信息
- `SYS_REBOOT_REASON` - 重启原因
- `SYS_KERNEL_LOG` - 内核日志
- `SYS_MINI_RDUMP` / `SYS_COREDUMP` - 内存转储
- `symbols/vmlinux` - 符号文件
- `SYS_MODULES_INFO` - 内核模块信息
- `out.json` - 解析输出

## 输出内容

生成的报告包含以下章节：

1. **基本信息** - Crash ID, 异常类型, 时间, 平台等
2. **进程信息** - 当前进程和父进程信息
3. **崩溃位置** - PC 和 LR 寄存器值
4. **调用栈** - 完整的 backtrace
5. **根因分析** - 自动分析的可能原因
6. **涉及模块** - 识别出的相关内核模块
7. **关键日志片段** - 崩溃前后的重要日志
8. **修复建议** - 针对性的修复建议
9. **构建信息** - 版本和构建信息
10. **内核版本** - 内核版本信息

## Crash Dump 目录结构

```
db.fatal.XX.KE.dbg.DEC/
├── __exp_main.txt          # 异常主要信息
├── SYS_REBOOT_REASON       # 重启原因
├── SYS_KERNEL_LOG          # 内核日志
├── SYS_MINI_RDUMP          # Mini dump (可选)
├── SYS_COREDUMP            # 完整 dump (可选)
├── SYS_MODULES_INFO        # 模块信息
├── SYS_EXTRA_BLOCKIO_RAW   # IO 信息
├── SYS_CUR_PLLK           # Bootloader log
├── out.json               # 解析输出
├── symbols/
│   └── vmlinux            # 符号文件
└── _分析报告.txt           # 现有分析报告
```

## 调试工具依赖

本分析器主要依赖 Python 标准库，不需要额外的调试工具。但建议安装以下工具以获得更完整的分析：

```bash
# ARM64 调试工具 (可选)
sudo apt-get install gdb-multiarch crash binutils-aarch64-linux-gnu
```

## 扩展开发

可以通过继承 `LocalCrashDumpAnalyzer` 类来扩展功能：

```python
from local_analyzer import LocalCrashDumpAnalyzer

class CustomAnalyzer(LocalCrashDumpAnalyzer):
    def _analyze_root_cause(self, basic_info, backtrace, cpu_states):
        # 自定义根因分析逻辑
        custom_analysis = "..."
        return custom_analysis
    
    def _generate_recommendations(self, basic_info, root_cause):
        # 自定义修复建议
        custom_recs = [...]
        return custom_recs
```

## 集成到 ke-analyzer

可以在 `orchestrator` 或 `agent` 模块中调用本地分析器：

```python
from local_analyzer import analyze_crash_dump

class CrashAnalyzer:
    async def analyze_local_dump(self, dump_dir: str) -> str:
        analysis, report_path = await analyze_crash_dump(
            dump_dir, 
            self.output_dir
        )
        return report_path
```
