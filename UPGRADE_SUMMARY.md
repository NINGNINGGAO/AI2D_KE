# KE Analyzer - 汇编层次分析功能升级总结

## 升级概述

本次升级为 KE Analyzer 增加了强大的**汇编层次分析能力**，能够结合寄存器信息和汇编指令对 crash dump 进行深度分析，识别 bitflip、内存破坏、空指针等底层问题。

## 新增功能清单

### 1. 核心分析模块 (`tools/asm_analyzer.py`)

#### 1.1 数据结构

| 类名 | 用途 |
|-----|------|
| `RegisterState` | 寄存器状态跟踪，自动检测可疑值 |
| `AsmInstruction` | 汇编指令解析，识别指令类型和寄存器 |
| `FunctionAsmAnalysis` | 函数级汇编分析结果 |

#### 1.2 检测能力

| 检测类型 | 实现功能 |
|---------|---------|
| **空指针检测** | 检测对 X0/X1 等 NULL 寄存器的内存访问 |
| **位翻转检测** | 识别单/双位翻转模式，计算翻转位位置 |
| **内存访问异常** | 检测大偏移、非对齐访问、异常地址范围 |
| **可疑值检测** | 识别近似 NULL、稀疏位模式、异常高位地址 |

#### 1.3 关键方法

```python
# 解析汇编输出
parse_assembly_output(asm_output, function_name) -> FunctionAsmAnalysis

# 结合寄存器分析
analyze_with_registers(asm_analysis, registers, crashed_address) -> FunctionAsmAnalysis

# 位翻转检测
detect_bitflip(value, expected_range) -> Optional[Dict]

# 生成分析报告
generate_analysis_report(asm_analysis) -> Dict[str, Any]

# 便捷函数
analyze_crash_with_assembly(asm_output, registers, crashed_address, function_name)
```

### 2. GDB 工具增强 (`tools/gdb_tool.py`)

新增 3 个方法：

```python
# 获取函数汇编及上下文
get_function_assembly_with_context(vmlinux_path, function_name, core_file)

# 分析崩溃点寄存器状态
analyze_crash_point_registers(vmlinux_path, crashed_pc, core_file)

# 获取带完整上下文的调用栈
get_backtrace_with_full_context(vmlinux_path, core_file, max_frames)
```

### 3. VMCORE 解析器增强 (`extractor/vmcore_parser.py`)

新增汇编分析流程：

```python
async def _perform_assembly_analysis(vmcore_path, vmlinux_path, parse_result):
    """
    执行汇编层次分析：
    1. 获取崩溃点上下文
    2. 分析调用栈前3帧的汇编
    3. 检测位翻转
    4. 识别可疑模式
    """
```

### 4. Context Builder 增强 (`extractor/context_builder.py`)

- 新增 `assembly_analysis` 字段到上下文
- 新增 `_extract_assembly_analysis()` 方法
- 新增 `_format_assembly_analysis()` 方法
- 新增 Context Block: `assembly_analysis`

### 5. AI 提示词增强 (`agent/prompt_templates.py`)

新增 2 个提示词模板：

```python
# 汇编层次深度分析
assembly_level_analysis_prompt(context) -> str

# 内存破坏专门分析
memory_corruption_analysis_prompt(context) -> str
```

### 6. AI 分析器增强 (`agent/analyzer.py`)

集成汇编分析到 AI 流程：

```python
async def analyze(context):
    # 1. 基础分析
    basic_result = await basic_analysis(context)
    
    # 2. 汇编层次分析（新增）
    if asm_analysis_available:
        asm_result = await assembly_level_analysis(context)
        basic_result['assembly_analysis'] = asm_result
        
        # 3. 内存破坏专门分析（如果检测到异常）
        if has_anomalies:
            mem_result = await memory_corruption_analysis(context)
            basic_result['memory_corruption_analysis'] = mem_result
```

## 实际案例分析

### 用户提供的 Crash 案例

**崩溃信息**:
- CPU3: kworker/3:1H, pid: 26858
- Crash PC: `0xFFFFFFE91B368DAC`
- Function: `__queue_work+40`
- 指令: `LDRB W8, [X1, #0x102]`

**寄存器状态**:
```
X0: 0x0000000000000000  (NULL)
X1: 0x0000000000000000  (NULL)
X8: 0x0000000000000000  (NULL)
X9: 0x0000000100000102  (可疑 - 可能是位翻转)
```

**分析结果**:

```
==================================================
ANOMALIES:
==================================================
1. [CRITICAL] null_pointer
   Address: 0xffffffe91b368dac
   Instruction: ldrb w8, [x1, #258]
   Description: ldrb accessing NULL pointer via X1

2. [CRITICAL] null_pointer
   Address: 0xffffffe91b368db4
   Instruction: ldr x8, [x0, #8]
   Description: ldr accessing NULL pointer via X0

... (共 9 个空指针异常)

==================================================
KEY FINDINGS:
==================================================
• Found 9 CRITICAL anomalies suggesting null pointer or severe corruption

==================================================
RECOMMENDATIONS:
==================================================
• Check for missing NULL pointer checks in the code path
• Review pointer initialization and validation logic
```

## 技术实现细节

### 1. 汇编解析

支持多种 GDB/crash 输出格式：

```
# 格式1: 标准格式
0xffffffe91b368dac <__queue_work+40>:    ldrb    w8, [x1, #258]

# 格式2: 简化格式
0xffffffe91b368dac: ldrb w8, [x1, #258]

# 格式3: 当前指令标记
=> 0xffffffe91b368dac <__queue_work+40>:    ldrb    w8, [x1, #258]
```

### 2. 寄存器解析

支持 ARM64 寄存器命名：

```python
# 通用寄存器
W0-W30 (32-bit), X0-X30 (64-bit)

# 特殊寄存器
SP - 栈指针
LR/X30 - 链接寄存器
FP/X29 - 帧指针
PC - 程序计数器
XZR/WZR - 零寄存器
```

### 3. 指令类型识别

| 类型 | 指令示例 |
|-----|---------|
| LOAD | LDR, LDRB, LDRH, LDUR, LDP, LDP, LDAR, LDXR |
| STORE | STR, STRB, STRH, STUR, STP, STNP, STLR, STXR |
| ARITHMETIC | ADD, SUB, MUL, DIV, SDIV, UDIV, SMULL |
| LOGICAL | AND, ORR, EOR, ORN, BIC, BICS |
| BRANCH | B, BL, BR, BLR, RET, CBZ, CBNZ, TBZ, TBNZ |
| MOVE | MOV, MVN, MOVK, MOVZ, MOVN |
| COMPARE | CMP, CMN, TST |

### 4. 位翻转检测算法

```python
def detect_bitflip(value, expected_range):
    # 1. 检查单一位翻转
    for bit_pos in range(64):
        flipped = value ^ (1 << bit_pos)
        if flipped in expected_range:
            return {
                'detected': True,
                'bit_position': bit_pos,
                'confidence': 'HIGH'
            }
    
    # 2. 检查双位翻转
    for bit1 in range(64):
        for bit2 in range(bit1 + 1, 64):
            flipped = value ^ (1 << bit1) ^ (1 << bit2)
            if flipped in expected_range:
                return {
                    'detected': True,
                    'bit_positions': [bit1, bit2],
                    'confidence': 'MEDIUM'
                }
```

## 文件变更清单

### 新增文件

1. `tools/asm_analyzer.py` - 汇编分析核心模块 (23KB+)
2. `tools/__init__.py` - 工具包导出 (新增)
3. `examples/asm_analysis_demo.py` - 演示脚本 (10KB+)
4. `docs/ASSEMBLY_ANALYSIS.md` - 功能文档 (8KB+)

### 修改文件

1. `tools/gdb_tool.py` - 新增 3 个方法 (+150 行)
2. `extractor/vmcore_parser.py` - 集成汇编分析 (+120 行)
3. `extractor/context_builder.py` - 新增汇编上下文 (+80 行)
4. `agent/prompt_templates.py` - 新增 2 个提示词模板 (+100 行)
5. `agent/analyzer.py` - 集成汇编分析到 AI 流程 (+30 行)

## 使用方式

### 自动集成

汇编分析已自动集成到现有流程中：

```python
# 解析 vmcore 时自动执行
result = await vmcore_parser.parse(vmcore_path, vmlinux_path)

# 结果中包含汇编分析
assembly_analysis = result['assembly_analysis']
```

### 手动调用

```python
from tools.asm_analyzer import analyze_crash_with_assembly

report = analyze_crash_with_assembly(
    asm_output=gdb_disassembly_output,
    registers=crash_registers,
    crashed_address='0xFFFFFFE91B368DAC',
    function_name='__queue_work'
)

# 查看异常
for anomaly in report['anomalies']:
    print(f"[{anomaly['severity']}] {anomaly['type']}")
    print(f"  {anomaly['description']}")
```

## 运行演示

```bash
cd /home/agogin/.openclaw/workspace/ke-analyzer
PYTHONPATH=/home/agogin/.openclaw/workspace/ke-analyzer:$PYTHONPATH \
  python3 examples/asm_analysis_demo.py
```

## 后续建议

1. **性能优化**: 对于大型 vmcore，汇编分析可能需要优化
2. **架构扩展**: 支持 x86/x86_64 架构的汇编分析
3. **历史对比**: 实现回归检测，对比历史分析结果
4. **可视化**: 添加汇编代码的图形化展示

## 总结

本次升级使 KE Analyzer 具备了**指令级别的 crash 分析能力**，能够：

- ✅ 自动识别空指针访问
- ✅ 检测位翻转（硬件故障指示）
- ✅ 识别内存破坏模式
- ✅ 跟踪寄存器状态变化
- ✅ 提供具体的修复建议
- ✅ 区分软件 bug 和硬件问题

这些功能将大大提高 kernel crash 分析的效率和准确性，特别是对于难以复现的随机崩溃问题。
