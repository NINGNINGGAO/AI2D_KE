# KE Analyzer - v1.1 变更总结与快速参考

**版本**: 1.1  
**发布日期**: 2026-02-03  
**主要更新**: 汇编层次分析 + 内核源码分析接口

---

## 📋 变更清单

### 新增文件 (7个)

| 文件 | 大小 | 说明 |
|------|------|------|
| `tools/asm_analyzer.py` | 23KB | 汇编层次分析核心模块 |
| `tools/source_analyzer.py` | 16KB | 内核源码分析接口 (预留) |
| `tools/__init__.py` | 新增 | 工具包导出文件 |
| `examples/asm_analysis_demo.py` | 10KB | 汇编分析演示脚本 |
| `docs/ASSEMBLY_ANALYSIS.md` | 8KB | 汇编功能详细文档 |
| `TECHNICAL_DOCUMENTATION_v1.1.md` | 22KB | 更新版技术文档 |
| `UPGRADE_SUMMARY.md` | 7KB | 升级内容总结 |

### 修改文件 (7个)

| 文件 | 变更内容 | 行数变化 |
|------|---------|---------|
| `README.md` | 更新架构图、功能说明、配置项 | 重写 |
| `TECHNICAL_DOCUMENTATION.md` | 保留原版本 | - |
| `orchestrator/config.py` | 新增汇编和源码分析配置 | +15 |
| `tools/gdb_tool.py` | 新增 3 个汇编相关方法 | +150 |
| `tools/__init__.py` | 导出新模块 | 新增 |
| `extractor/vmcore_parser.py` | 集成汇编分析 | +120 |
| `extractor/context_builder.py` | 新增汇编上下文 | +80 |
| `agent/prompt_templates.py` | 新增 2 个提示词模板 | +100 |
| `agent/analyzer.py` | 集成汇编分析 | +30 |
| `.env.example` | 新增配置示例 | 新增 |

---

## 🚀 快速开始

### 1. 启动服务

```bash
cd /home/agogin/.openclaw/workspace/ke-analyzer

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填入必要的配置

# 启动服务
python -m orchestrator.main
```

### 2. 运行演示

```bash
# 运行汇编分析演示
PYTHONPATH=/home/agogin/.openclaw/workspace/ke-analyzer:$PYTHONPATH \
  python3 examples/asm_analysis_demo.py
```

### 3. 测试 Webhook

```bash
# 发送测试请求
curl -X POST http://localhost:8000/webhook/jira \
  -H "Content-Type: application/json" \
  -d '{
    "webhookEvent": "jira:issue_created",
    "issue": {
      "key": "TEST-123",
      "fields": {
        "summary": "Kernel crash in __queue_work",
        "description": "NULL pointer dereference detected"
      }
    }
  }'
```

---

## 🔧 配置速查

### 汇编分析配置

```bash
# 启用/禁用汇编分析
ENABLE_ASSEMBLY_ANALYSIS=true

# 分析的指令数量 (默认 30)
MAX_ASM_CONTEXT_INSTRUCTIONS=30

# 位翻转检测
BITFLIP_DETECTION_ENABLED=true
```

### 源码分析配置 (预留)

```bash
# 内核源码路径 (预留)
KERNEL_SOURCE_PATH=/path/to/android/kernel

# 分析后端 (当前仅 stub)
SOURCE_ANALYZER_BACKEND=stub
```

---

## 📖 接口使用指南

### 汇编分析接口

```python
from tools.asm_analyzer import analyze_crash_with_assembly

# 基本用法
report = analyze_crash_with_assembly(
    asm_output=gdb_disassembly_output,  # GDB 汇编输出
    registers={
        'x0': '0x0000000000000000',
        'x1': '0xFFFFFF80D12F7A80',
        'pc': '0xFFFFFFE91B368DAC',
    },
    crashed_address='0xFFFFFFE91B368DAC',
    function_name='__queue_work'
)

# 查看结果
print(f"发现 {report['suspicious_instruction_count']} 条可疑指令")
for anomaly in report['anomalies']:
    print(f"[{anomaly['severity']}] {anomaly['type']}")
```

### 高级用法

```python
from tools.asm_analyzer import AssemblyAnalyzer

analyzer = AssemblyAnalyzer()

# 解析汇编
asm_analysis = analyzer.parse_assembly_output(asm_output, function_name)

# 结合寄存器分析
asm_analysis = analyzer.analyze_with_registers(
    asm_analysis, registers, crashed_address
)

# 检测位翻转
result = analyzer.detect_bitflip(0x0000000000000001)
if result and result['detected']:
    print(f"位翻转检测: bit {result['bit_position']}")

# 生成报告
report = analyzer.generate_analysis_report(asm_analysis)
```

### 源码分析接口 (预留)

```python
from tools.source_analyzer import get_source_analyzer

# 获取分析器 (当前返回 stub)
analyzer = await get_source_analyzer()

# 查找符号 (stub 返回占位符)
symbol = await analyzer.lookup_symbol("__queue_work")
print(f"{symbol.name} at {symbol.location}")

# 地址映射 (stub 返回占位符)
location = await analyzer.lookup_address(
    "0xffffffe91b368dac", "/path/to/vmlinux"
)
```

---

## 📊 分析输出示例

### 汇编分析报告

```json
{
  "function": "__queue_work",
  "instruction_count": 14,
  "suspicious_instruction_count": 9,
  "anomalies": [
    {
      "type": "null_pointer",
      "severity": "CRITICAL",
      "address": "0xffffffe91b368dac",
      "instruction": "ldrb w8, [x1, #258]",
      "description": "ldrb accessing NULL pointer via X1",
      "register": {"name": "X1", "value": "0x0", "is_null": true}
    }
  ],
  "bitflip_detection": {
    "detected": true,
    "original_value": "0x1",
    "flipped_value": "0x0",
    "bit_position": 0,
    "confidence": "HIGH"
  },
  "key_findings": [
    "Found 9 CRITICAL anomalies suggesting null pointer or severe corruption"
  ],
  "recommendations": [
    "Check for missing NULL pointer checks in the code path",
    "Review pointer initialization and validation logic",
    "Consider hardware issues (RAM/ECC errors) or radiation effects"
  ]
}
```

---

## 🔍 故障排查

### 汇编分析相关问题

**问题**: 汇编分析未执行
```bash
# 检查配置
grep ENABLE_ASSEMBLY_ANALYSIS .env

# 检查日志
docker logs ke-analyzer | grep -i "assembly"
```

**问题**: 寄存器解析失败
```bash
# 确保 GDB 可用
which gdb
gdb --version

# 检查 vmlinux 包含调试信息
file /path/to/vmlinux
# 应显示: "not stripped"
```

**问题**: 位翻转检测误报
```bash
# 调整检测阈值 (修改源码)
# tools/asm_analyzer.py
# 修改 detect_bitflip 方法的 expected_range 参数
```

### 源码分析问题 (预留)

**问题**: 源码分析返回 stub 数据
```
这是预期行为。当前源码分析接口为预留状态，
返回占位符数据。待接入完整内核源码后，
替换为真实后端实现 (cscope/clang/lsp)。
```

---

## 📚 文档索引

| 文档 | 路径 | 说明 |
|------|------|------|
| 快速开始 | `README.md` | 安装、配置、使用指南 |
| 技术架构 | `TECHNICAL_DOCUMENTATION_v1.1.md` | 详细架构设计 |
| 汇编分析 | `docs/ASSEMBLY_ANALYSIS.md` | 汇编功能详细文档 |
| 升级总结 | `UPGRADE_SUMMARY.md` | v1.1 升级内容总结 |
| 配置示例 | `.env.example` | 环境变量配置模板 |
| API 文档 | `http://localhost:8000/docs` | Swagger UI (运行时) |

---

## 🗺️ 路线图

### Phase 1: 完善汇编分析 (当前 - v1.1) ✅
- [x] 基础汇编解析
- [x] 寄存器跟踪
- [x] 位翻转检测
- [ ] x86/x86_64 架构支持

### Phase 2: 源码接入 (v1.2)
- [ ] Cscope 后端实现
- [ ] 地址-源码映射
- [ ] 基础交叉引用

### Phase 3: 深度分析 (v1.3)
- [ ] Clang 静态分析后端
- [ ] 代码路径分析
- [ ] 变量生命周期跟踪

### Phase 4: 智能联合分析 (v1.4)
- [ ] 源码 + 汇编 + AI 联合推理
- [ ] 自动修复建议生成
- [ ] 历史回归检测

---

## 💡 使用技巧

### 1. 调试汇编分析

```python
import logging
logging.getLogger('tools.asm_analyzer').setLevel(logging.DEBUG)
```

### 2. 手动验证位翻转

```python
from tools.asm_analyzer import AssemblyAnalyzer

analyzer = AssemblyAnalyzer()

# 测试值
test_values = [
    0x0000000000000001,  # 可能是 0x0 的第 0 位翻转
    0x0000000100000000,  # 可能是 0x0 的第 32 位翻转
]

for value in test_values:
    result = analyzer.detect_bitflip(value)
    print(f"{value:#x}: {result}")
```

### 3. 查看调用日志 (stub)

```python
from tools.source_analyzer import KernelSourceAnalyzerStub

analyzer = KernelSourceAnalyzerStub()
await analyzer.initialize("/path/to/kernel")

# 执行操作...

# 查看调用日志
log = analyzer.get_call_log()
for entry in log:
    print(f"{entry['method']}: {entry['params']}")
```

---

## 🔗 相关链接

- [ARM64 指令集参考](https://developer.arm.com/documentation/)
- [Linux Kernel Crash Dump Analysis](https://www.kernel.org/doc/html/latest/admin-guide/kdump/)
- [GDB Python API](https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html)
- [Qwen-Max API 文档](https://help.aliyun.com/document_detail/611472.html)

---

## 📞 获取帮助

- **GitHub Issues**: 提交 bug 报告或功能请求
- **文档**: 查看 `docs/` 目录下的详细文档
- **演示**: 运行 `examples/asm_analysis_demo.py`

---

*文档结束 - 祝分析愉快! 🎯*
