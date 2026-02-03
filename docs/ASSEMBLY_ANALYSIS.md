# KE Analyzer - 汇编层次分析功能

## 功能概述

新增的汇编层次分析功能可以对 kernel crash 进行深度分析，通过结合寄存器信息和汇编指令，帮助识别：

- **空指针访问** (NULL Pointer Dereference)
- **位翻转** (Bitflip) - 由硬件故障、辐射或内存问题导致
- **内存破坏** (Memory Corruption) - 越界访问、use-after-free、double-free
- **栈破坏** (Stack Corruption)
- **DMA 破坏** (DMA Corruption)

## 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                     汇编层次分析流程                              │
└─────────────────────────────────────────────────────────────────┘

Crash Dump (vmcore) + vmlinux
         │
         ▼
┌─────────────────────┐
│   crash_tool        │ ──▶ 获取基本调用栈、寄存器
│   (基本解析)         │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   gdb_tool          │ ──▶ 获取详细汇编代码
│   (汇编提取)         │     • 函数反汇编
│                     │     • 崩溃点上下文
└─────────────────────┘     • 寄存器状态
         │
         ▼
┌─────────────────────┐
│   asm_analyzer      │ ──▶ 深度分析
│   (汇编分析)         │     • 指令级跟踪
│                     │     • 寄存器值分析
│                     │     • 位翻转检测
│                     │     • 异常模式识别
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   AI Analysis       │ ──▶ 智能推理
│   (Qwen-Max)        │     • 根因分析
│                     │     • 修复建议
│                     │     • 硬件/软件问题判断
└─────────────────────┘
```

## 核心组件

### 1. AssemblyAnalyzer (asm_analyzer.py)

主分析器类，提供以下功能：

#### 1.1 寄存器状态跟踪 (RegisterState)

```python
@dataclass
class RegisterState:
    name: str
    value: str
    value_int: int
    is_null: bool          # 是否为 NULL
    is_suspicious: bool    # 是否可疑
    suspicious_reason: str # 可疑原因
```

**可疑模式检测**:
- 单/双位设置模式（可能是位翻转）
- 近似 NULL 的地址
- 异常高位地址

#### 1.2 指令解析 (AsmInstruction)

```python
@dataclass
class AsmInstruction:
    address: str
    instruction: str      # 指令名 (LDR, STR, ADD, etc.)
    operands: str         # 操作数
    inst_type: InstructionType  # 指令类型
    read_regs: List[str]  # 读取的寄存器
    write_regs: List[str] # 写入的寄存器
    memory_access: bool   # 是否内存访问
    memory_address_reg: str  # 基址寄存器
    memory_offset: int    # 偏移量
    anomalies: List[Dict] # 检测到的异常
```

#### 1.3 异常类型 (AnomalyType)

| 类型 | 说明 |
|-----|------|
| `NULL_POINTER` | 空指针访问 |
| `BITFLIP` | 位翻转检测 |
| `MEMORY_CORRUPTION` | 内存破坏 |
| `STACK_CORRUPTION` | 栈破坏 |
| `USE_AFTER_FREE` | 释放后使用 |
| `OUT_OF_BOUNDS` | 越界访问 |
| `UNINITIALIZED` | 未初始化使用 |

### 2. GDB 工具增强 (gdb_tool.py)

新增方法：

```python
# 获取函数汇编及上下文
async def get_function_assembly_with_context(
    vmlinux_path, function_name, core_file, context_instructions=20
) -> Dict[str, Any]

# 分析崩溃点寄存器状态
async def analyze_crash_point_registers(
    vmlinux_path, crashed_pc, core_file
) -> Dict[str, Any]

# 获取带完整上下文的调用栈
async def get_backtrace_with_full_context(
    vmlinux_path, core_file, max_frames=10
) -> List[Dict[str, Any]]
```

### 3. VMCORE 解析器增强 (vmcore_parser.py)

新增 `_perform_assembly_analysis` 方法：

```python
async def _perform_assembly_analysis(
    self, vmcore_path, vmlinux_path, parse_result
) -> Dict[str, Any]:
    """
    执行汇编层次分析，包括：
    1. 获取崩溃点上下文
    2. 分析调用栈前3帧的汇编
    3. 检测位翻转
    4. 识别可疑模式
    """
```

### 4. AI 提示词增强 (prompt_templates.py)

新增模板：

- `assembly_level_analysis_prompt` - 汇编层次深度分析
- `memory_corruption_analysis_prompt` - 内存破坏专门分析

## 使用示例

### 基础用法

```python
from tools.asm_analyzer import analyze_crash_with_assembly

# 分析 crash 的汇编层次信息
report = analyze_crash_with_assembly(
    asm_output=gdb_disassembly_output,
    registers={
        'x0': '0x0000000000000000',
        'x1': '0xFFFFFF80D12F7A80',
        # ... 其他寄存器
    },
    crashed_address='0xFFFFFFE91B368DAC',
    function_name='__queue_work'
)

# 查看分析结果
print(f"Anomalies: {report['suspicious_instruction_count']}")
for anomaly in report['anomalies']:
    print(f"[{anomaly['severity']}] {anomaly['type']}: {anomaly['description']}")
```

### 高级用法

```python
from tools.asm_analyzer import AssemblyAnalyzer

analyzer = AssemblyAnalyzer()

# 解析汇编输出
asm_analysis = analyzer.parse_assembly_output(
    asm_output=gdb_output,
    function_name='__queue_work'
)

# 结合寄存器分析
asm_analysis = analyzer.analyze_with_registers(
    asm_analysis,
    registers=crash_registers,
    crashed_address='0xFFFFFFE91B368DAC'
)

# 位翻转检测
bitflip_result = analyzer.detect_bitflip(
    value=0x0000000000000001,
    expected_range=(0xFFFFFF0000000000, 0xFFFFFFFFFFFFFFFF)
)

if bitflip_result and bitflip_result['detected']:
    print(f"Possible bitflip at bit {bitflip_result['bit_position']}")

# 生成完整报告
report = analyzer.generate_analysis_report(asm_analysis)
```

## 分析输出示例

### 异常检测报告

```json
{
  "anomalies": [
    {
      "type": "null_pointer",
      "severity": "CRITICAL",
      "description": "LDRB accessing NULL pointer via X1",
      "address": "0xFFFFFFE91B368DAC",
      "instruction": "ldrb w8, [x1, #258]",
      "register": {
        "name": "X1",
        "value": "0x0000000000000000",
        "is_null": true
      }
    },
    {
      "type": "bitflip",
      "severity": "HIGH", 
      "description": "Suspicious memory access via X9 (Near-null address)",
      "address": "0xFFFFFFE91B368DD4",
      "instruction": "ldr x9, [x8, #48]"
    }
  ],
  "bitflip_detection": {
    "detected": true,
    "original_value": "0x0000000000000001",
    "flipped_value": "0x0000000000000000",
    "bit_position": 0,
    "confidence": "HIGH"
  }
}
```

### 分析报告

```
Assembly-Level Analysis:
  Crash PC: 0xFFFFFFE91B368DAC
  Anomalies Found: 2

  Bitflip Detection:
    Original: 0x0000000000000001
    Flipped: 0x0000000000000000
    Bit Position: 0
    Confidence: HIGH

  Detected Anomalies:
    1. [CRITICAL] null_pointer
       LDRB accessing NULL pointer via X1
       Function: __queue_work

    2. [HIGH] bitflip
       Suspicious memory access via X9 (Near-null address)
       Function: __queue_work

  Recommendations:
    - Check for missing NULL pointer checks in the code path
    - Review pointer initialization and validation logic
    - Consider hardware issues (RAM/ECC errors) or radiation effects
    - Check for DMA corruption or driver bugs
```

## 集成到分析流程

汇编分析已自动集成到现有的分析流程中：

1. **vmcore_parser** 在解析 vmcore 时自动执行汇编分析
2. **context_builder** 将汇编分析结果纳入上下文
3. **analyzer** 使用专门的提示词模板进行 AI 分析
4. **最终报告** 包含汇编层次的发现和建议

## 检测能力

### 1. 空指针检测

```asm
; 检测模式
ldrb w8, [x1, #258]   ; X1 = 0x0 → NULL pointer access
ldr  x9, [x8, #48]    ; X8 = 0x0 → NULL pointer access
```

### 2. 位翻转检测

```python
# 检测算法
# 1. 检查稀疏位模式 (1-2 个位设置)
# 2. 尝试翻转每一位，看是否能得到合理值
# 3. 检查双位翻转

# 示例
0x0000000000000001  # 可能是 0x0 的第 0 位翻转
0x0000000100000000  # 可能是 0x0 的第 32 位翻转
```

### 3. 内存访问异常检测

- **大偏移量**: offset > 0x10000 可能是越界
- **非对齐访问**: address & 0x7 != 0
- **异常地址范围**: 用户空间地址、无效内核地址

### 4. 指令模式分析

```asm
; 栈操作检测
stp x29, x30, [sp, #-16]!   ; 函数序言
ldp x29, x30, [sp], #16      ; 函数尾声

; 分支检测
blr x0                       ; 间接调用，检查 X0 是否有效
cbz x1, label               ; 条件分支
```

## 硬件问题识别

基于汇编分析可以识别以下硬件相关问题：

| 症状 | 可能原因 | 检测方法 |
|-----|---------|---------|
| 单一位翻转 | RAM 故障、辐射 | bitflip 检测 |
| 多位翻转 | 严重的内存故障 | 稀疏位模式检测 |
| 随机崩溃 | 电源问题、过热 | 异常地址分布分析 |
| DMA 破坏 | 设备驱动问题 | 内存内容分析 |

## 配置选项

在 `.env` 文件中可以配置：

```bash
# 汇编分析设置
ENABLE_ASSEMBLY_ANALYSIS=true
MAX_ASM_CONTEXT_INSTRUCTIONS=30  # 获取的汇编指令数量
BITFLIP_DETECTION_ENABLED=true
```

## 性能考虑

- 汇编分析会增加分析时间（约 10-30 秒）
- 默认只分析调用栈的前 3 帧
- 可以禁用汇编分析以提高速度

## 调试技巧

1. **查看详细汇编输出**:
   ```bash
   python examples/asm_analysis_demo.py
   ```

2. **检查寄存器状态**:
   ```python
   from tools.asm_analyzer import RegisterState
   reg = RegisterState(name='X0', value='0x0000000000000000')
   print(f"Is NULL: {reg.is_null}, Suspicious: {reg.is_suspicious}")
   ```

3. **手动验证位翻转**:
   ```python
   from tools.asm_analyzer import AssemblyAnalyzer
   analyzer = AssemblyAnalyzer()
   result = analyzer.detect_bitflip(0x0000000000000001)
   ```

## 未来扩展

- [ ] 支持 x86/x86_64 架构的汇编分析
- [ ] 集成符号执行进行更深层的分析
- [ ] 支持历史数据对比（回归检测）
- [ ] 集成硬件遥测数据（温度、电压）
- [ ] 机器学习模型训练用于异常检测

## 参考

- [ARM64 Instruction Set Reference](https://developer.arm.com/documentation/)
- [Linux Kernel Crash Dump Analysis](https://www.kernel.org/doc/html/latest/admin-guide/kdump/)
- [GDB Python API](https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html)
