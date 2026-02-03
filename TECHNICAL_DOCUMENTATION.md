# KE Analyzer - Android Kernel Crash 自动预分析系统

**技术架构文档**

版本: 1.0  
最后更新: 2026-02-03  
作者: OpenClaw  

---

## 目录

1. [系统概述](#1-系统概述)
2. [整体架构](#2-整体架构)
3. [模块详细设计](#3-模块详细设计)
4. [数据流分析](#4-数据流分析)
5. [配置管理](#5-配置管理)
6. [部署与运维](#6-部署与运维)
7. [扩展开发指南](#7-扩展开发指南)

---

## 1. 系统概述

### 1.1 项目背景

KE Analyzer 是一个专门为 Android 内核稳定性团队设计的自动化分析系统。它通过集成 Jira Webhook、AI 大模型分析能力和多种内核调试工具，实现对 Kernel Crash (KE) 问题的自动预分析。

### 1.2 核心目标

- **自动化**: 减少人工分析 KE 问题的重复劳动
- **智能化**: 利用 AI 辅助根本原因分析
- **知识沉淀**: 通过 Memory MCP 积累分析经验
- **协作增强**: 自动生成结构化报告，提升团队协作效率

### 1.3 支持的 Crash 类型

| Crash 类型 | 英文标识 | 检测方式 |
|-----------|---------|---------|
| 空指针解引用 | NULL Pointer Dereference | Log Pattern + vmcore |
| 内核 Oops | Kernel Oops | Log Pattern |
| 内核 Panic | Kernel Panic | Log Pattern |
| 页错误 | Page Fault | Log Pattern + vmcore |
| 看门狗超时 | Watchdog Timeout | Log Pattern |
| 软死锁 | Soft Lockup | Log Pattern |
| 硬死锁 | Hard Lockup | Log Pattern |
| 内核 BUG | Kernel BUG | Log Pattern |

---

## 2. 整体架构

### 2.1 架构图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              外部系统                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Jira   │    │  Qwen-Max│    │   crash      │    │  Memory MCP  │  │
│  │  Server  │    │   API    │    │   / gdb      │    │   Server     │  │
│  └────┬─────┘    └────┬─────┘    └──────┬───────┘    └──────┬───────┘  │
│       │               │                  │                   │          │
└───────┼───────────────┼──────────────────┼───────────────────┼──────────┘
        │               │                  │                   │
        │ Webhook       │ API              │ CLI               │ API
        │               │                  │                   │
┌───────┼───────────────┼──────────────────┼───────────────────┼──────────┐
│       ▼               │                  │                   ▼          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                        Orchestrator 层                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │
│  │  │   main.py    │  │state_manager │  │    jira_handler.py   │   │  │
│  │  │  FastAPI入口  │  │   状态管理    │  │    Webhook处理       │   │  │
│  │  └──────┬───────┘  └──────────────┘  └──────────────────────┘   │  │
│  │         │                                                        │  │
│  │  ┌──────┴─────────────────────────────────────────────────────┐  │  │
│  │  │                    Pipeline (分析流程)                       │  │  │
│  │  │  1. 下载附件 → 2. 信息提取 → 3. AI分析 → 4. 更新Jira       │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Extractor 层 (信息提取)                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │
│  │  │vmcore_parser │  │ log_parser   │  │   context_builder    │   │  │
│  │  │  vmcore解析  │  │ kernel log   │  │   上下文构建         │   │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                       Tools 层 (工具网关)                         │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │
│  │  │ crash_tool   │  │  gdb_tool    │  │   addr2line_tool     │   │  │
│  │  │ crash命令封装 │  │ gdb调试封装  │  │   地址转换工具       │   │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                       Agent 层 (AI分析)                           │  │
│  │  ┌──────────────┐  ┌──────────────┐                              │  │
│  │  │  analyzer.py │  │prompt_templates│                            │  │
│  │  │ Qwen-Max分析 │  │   提示词模板   │                            │  │
│  │  └──────────────┘  └──────────────┘                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Integration 层 (集成层)                        │  │
│  │  ┌──────────────┐  ┌──────────────┐                              │  │
│  │  │ jira/client  │  │mcp/memory_client│                           │  │
│  │  │ Jira API封装 │  │ Memory MCP客户端 │                           │  │
│  │  └──────────────┘  └──────────────┘                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 分层说明

| 层级 | 职责 | 核心模块 |
|-----|------|---------|
| **Orchestrator** | 服务入口、状态管理、流程编排 | `main.py`, `state_manager.py`, `jira_handler.py` |
| **Extractor** | 从附件中提取关键信息 | `vmcore_parser.py`, `log_parser.py`, `context_builder.py` |
| **Tools** | 封装内核调试工具 | `crash_tool.py`, `gdb_tool.py`, `addr2line_tool.py` |
| **Agent** | AI 分析与推理 | `analyzer.py`, `prompt_templates.py` |
| **Integration** | 外部系统集成 | `jira/client.py`, `mcp/memory_client.py` |

---

## 3. 模块详细设计

### 3.1 Orchestrator 层

#### 3.1.1 main.py - FastAPI 服务入口

**职责**: 提供 HTTP API 服务，处理 Jira Webhook，协调分析流程

**核心类/函数**:
```python
# FastAPI 应用实例
app = FastAPI(title="KE Analyzer", ...)

# Webhook 处理端点
@app.post("/webhook/jira")
async def jira_webhook(payload: JiraWebhookPayload, ...)

# 任务状态查询
@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str)

# 后台分析任务
async def run_analysis_pipeline(task_id: str)
```

**Webhook 支持的事件**:
- `jira:issue_created`: 创建新问题时触发
- `jira:issue_updated`: 添加附件时触发

**API 端点**:
| 端点 | 方法 | 说明 |
|-----|------|-----|
| `/` | GET | 服务状态 |
| `/health` | GET | 健康检查 |
| `/webhook/jira` | POST | Jira Webhook |
| `/tasks/{task_id}` | GET | 任务状态查询 |
| `/tasks` | GET | 任务列表 |

#### 3.1.2 state_manager.py - 状态管理

**职责**: 管理分析任务的生命周期，持久化任务状态

**核心数据结构**:
```python
class AnalysisStatus(Enum):
    PENDING = "pending"         # 等待处理
    DOWNLOADING = "downloading" # 下载附件中
    EXTRACTING = "extracting"   # 提取信息中
    ANALYZING = "analyzing"     # AI 分析中
    COMPLETED = "completed"     # 分析完成
    FAILED = "failed"           # 分析失败
    SKIPPED = "skipped"         # 跳过（无附件）

@dataclass
class AnalysisTask:
    task_id: str
    issue_key: str
    issue_id: str
    summary: str
    description: str
    status: AnalysisStatus
    created_at: str
    updated_at: str
    attachments: Dict[str, Any]
    downloaded_files: Dict[str, str]
    extracted_info: Dict[str, Any]
    analysis_result: Optional[Dict[str, Any]]
    error_message: Optional[str]
    jira_comment_id: Optional[str]
```

**状态转换图**:
```
┌─────────┐    创建    ┌─────────┐   下载附件   ┌───────────┐
│  INIT   │ ─────────▶ │ PENDING │ ──────────▶ │DOWNLOADING│
└─────────┘            └─────────┘             └─────┬─────┘
                                                     │
           ┌─────────────────────────────────────────┘
           │
           ▼                                 分析完成
     ┌───────────┐    提取信息    ┌───────────┐ ───────▶ ┌───────────┐
     │  FAILED   │ ◀───────────── │EXTRACTING │          │ COMPLETED │
     └───────────┘                └─────┬─────┘          └───────────┘
           ▲                           │
           │                    AI分析   │
           └────────────────────────────┘
                              │
                              ▼
                        ┌───────────┐
                        │ ANALYZING │
                        └───────────┘
```

**持久化**: 任务状态自动保存到 `${WORK_DIR}/state.json`

#### 3.1.3 jira_handler.py - Webhook 处理器

**职责**: 解析 Jira Webhook 事件，创建分析任务

**核心方法**:
```python
class JiraWebhookHandler:
    async def handle_issue_created(self, payload: Dict) -> Optional[str]
    async def handle_issue_updated(self, payload: Dict) -> Optional[str]
    def _is_kernel_crash_issue(self, summary: str, description: str) -> bool
    def _extract_attachment_info(self, attachments: list) -> Dict[str, Any]
```

**附件识别规则**:
| 文件类型 | 识别模式 | 存储键 |
|---------|---------|-------|
| vmcore | `vmcore` in filename 或 `.dump` | `vmcore` |
| vmlinux | `vmlinux` in filename 或 `.elf` | `vmlinux` |
| kernel log | `kern` in filename 或 `.log`/`.txt` | `kern_log` |

**KE 类型检测关键词**:
```python
ke_keywords = [
    'kernel crash', 'ke ', 'ke:', 'ke-', 'panic', 'oops',
    'null pointer', 'watchdog', 'softlockup', 'hardlockup',
    '内核崩溃', '空指针', '看门狗', '死锁'
]
```

---

### 3.2 Extractor 层

#### 3.2.1 vmcore_parser.py - VMCORE 解析器

**职责**: 使用 crash 工具解析 vmcore 文件，提取调用栈、寄存器、模块信息

**核心方法**:
```python
class VmcoredParser:
    async def parse(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]
    def _parse_backtrace(self, bt_output: str) -> List[Dict[str, str]]
    def _parse_registers(self, reg_output: str) -> Dict[str, str]
    def _parse_modules(self, mod_output: str) -> List[Dict[str, str]]
    def _parse_system_info(self, sys_output: str) -> Dict[str, str]
    def _analyze_crash_type(self, call_stack, registers, raw_output) -> Optional[str]
```

**解析流程**:
1. 调用 `crash_tool.bt()` 获取调用栈
2. 调用 `crash_tool.regs()` 获取寄存器
3. 调用 `crash_tool.mod()` 获取加载模块
4. 调用 `crash_tool.sys()` 获取系统信息
5. 综合分析 crash 类型

**输出格式**:
```python
{
    'crash_type': 'NULL Pointer Dereference',
    'call_stack': [
        {'frame_num': '0', 'function': '__schedule', 'address': 'ffffffff81234567'},
        {'frame_num': '1', 'function': 'schedule', 'address': 'ffffffff81234589'},
    ],
    'registers': {
        'rax': '0000000000000000',
        'rbx': '0000000000000000',
        ...
    },
    'modules': [
        {'name': 'module1.ko', 'address': '0xffffffffc0000000', 'size': '16384'},
        ...
    ],
    'system_info': {
        'KERNEL': 'linux-5.10',
        'DUMPFILE': 'vmcore',
        ...
    },
    'error_info': None  # 或错误信息
}
```

#### 3.2.2 log_parser.py - Kernel Log 解析器

**职责**: 解析 kernel log 文件，识别 crash 类型和关键信息

**Crash 类型检测模式**:
```python
CRASH_PATTERNS = {
    CrashType.NULL_POINTER: [
        r'Unable to handle kernel NULL pointer dereference',
        r'null pointer dereference',
        r'Unable to handle kernel paging request at 0000000000000000',
    ],
    CrashType.KERNEL_OOPS: [
        r'Oops:.*\[.*\]',
        r'Oops:',
    ],
    CrashType.KERNEL_PANIC: [
        r'Kernel panic',
        r'---\[ end Kernel panic',
    ],
    # ... 其他类型
}
```

**信息提取**:
- **时间戳**: `\[\s*([\d.]+)\s*\]`
- **CPU**: `CPU[:\s]+(\d+)`
- **进程**: `[Cc]omm[:\s]+(\S+)`
- **PID**: `PID[:\s]+(\d+)`
- **调用栈**: 从日志中提取 `Call trace` 段落

**输出格式**:
```python
{
    'crash_found': True,
    'crash_info': {
        'type': 'NULL Pointer Dereference',
        'timestamp': '12345.678901',
        'cpu': 1,
        'process': 'test_process',
        'pid': 1234,
        'call_stack': ['function1+0x123/0x456', 'function2+0x789/0xabc', ...],
        'error_message': 'Unable to handle kernel NULL pointer dereference...'
    },
    'critical_logs': [
        {'level': 'CRITICAL', 'message': '...'},
        ...
    ],
    'summary': 'Found NULL Pointer Dereference in process \'test_process\' on CPU 1. Total log lines: 10000'
}
```

#### 3.2.3 context_builder.py - 上下文构建器

**职责**: 整合 vmcore 和 log 的解析结果，构建 AI 分析所需的完整上下文

**核心方法**:
```python
class ContextBuilder:
    def build(self, issue_summary, issue_description, extracted_info) -> Dict[str, Any]
    def _build_context_blocks(self, extracted_info) -> List[Dict[str, str]]
```

**上下文结构**:
```python
{
    'issue_info': {
        'summary': 'Issue summary from Jira',
        'description': 'Issue description from Jira'
    },
    'crash_analysis': {
        'crash_type': 'NULL Pointer Dereference',
        'timestamp': '12345.678901',
        'cpu': 1,
        'process': 'test_process',
        'pid': 1234,
        'error_details': '...'
    },
    'call_stack': [...],
    'modules': [...],
    'registers': {...},
    'system_info': {...},
    'raw_context_blocks': [  # 用于 Memory MCP
        {'block_id': 'issue_info', 'type': 'metadata', 'content': '...'},
        {'block_id': 'crash_info', 'type': 'error', 'content': '...'},
        {'block_id': 'call_stack', 'type': 'stacktrace', 'content': '...'},
        {'block_id': 'critical_logs', 'type': 'logs', 'content': '...'},
        {'block_id': 'system_info', 'type': 'system', 'content': '...'},
    ]
}
```

---

### 3.3 Tools 层

#### 3.3.1 crash_tool.py - Crash 工具网关

**职责**: 封装 Linux crash 工具，提供统一的命令执行接口

**核心类**:
```python
@dataclass
class CrashCommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    success: bool
    execution_time: float

class CrashToolGateway:
    def __init__(self, crash_cmd="crash", default_timeout=300, cache_enabled=True)
    
    # 通用执行方法
    async def execute(self, vmcore_path, command, vmlinux_path=None, ...) -> CrashCommandResult
    
    # 常用命令快捷方法
    async def get_backtrace(vmcore, vmlinux, all_cpus=True)
    async def get_sys_info(vmcore, vmlinux)
    async def get_ps_list(vmcore, vmlinux)
    async def get_modules(vmcore, vmlinux)
    async def get_log(vmcore, vmlinux)
    async def get_symbol_info(vmcore, address, vmlinux)
```

**支持的 Crash 命令**:
| 方法 | 命令 | 说明 |
|-----|------|-----|
| `get_backtrace` | `bt -a` / `bt` | 获取调用栈 |
| `get_sys_info` | `sys` | 系统信息 |
| `get_ps_list` | `ps` | 进程列表 |
| `get_modules` | `mod` | 加载模块 |
| `get_log` | `log` | 内核日志 |
| `get_symbol_info` | `sym {address}` | 符号信息 |
| `get_vm_info` | `vm` | 虚拟内存信息 |
| `get_pte` | `pte {address}` | 页表项 |

**缓存机制**:
- 基于 MD5(command + vmcore_path) 的缓存键
- 可配置启用/禁用
- 自动清理接口

#### 3.3.2 gdb_tool.py - GDB 工具网关

**职责**: 封装 GDB 调试工具，用于深入分析 crash 点

**核心方法**:
```python
class GDBToolGateway:
    async def execute(self, executable, commands, core_file=None, ...) -> GDBResult
    async def get_backtrace(self, executable, core_file, full=True)
    async def get_registers(self, executable, core_file)
    async def disassemble_function(self, executable, function_name, core_file)
    async def disassemble_address(self, executable, address, num_instructions=20, core_file)
    async def examine_memory(self, executable, address, format_spec="x", count=16, core_file)
    async def get_source_line(self, executable, address, core_file) -> Optional[Dict[str, str]]
    async def analyze_kernel_oops(self, vmlinux_path, fault_address, stack_trace) -> Dict[str, Any]
```

**应用场景**:
- 反汇编 crash 位置的代码
- 查看变量值
- 获取源代码行号映射
- 深入分析特定函数

#### 3.3.3 addr2line_tool.py - 地址转换工具

**职责**: 将内存地址转换为源代码文件和行号

**核心方法**:
```python
@dataclass
class Addr2LineResult:
    address: str
    function: str
    file: str
    line: int
    success: bool

class Addr2LineToolGateway:
    async def resolve(self, executable, address, use_inline=True, use_function=True) -> Addr2LineResult
    async def resolve_multiple(self, executable, addresses, ...) -> List[Addr2LineResult]
    async def resolve_stack_trace(self, executable, stack_trace) -> List[Dict[str, Any]]
    async def get_source_context(self, executable, address, context_lines=5) -> Dict[str, Any]
    def extract_addresses_from_text(self, text) -> List[str]
```

**应用示例**:
```python
# 解析整个调用栈
resolved = await addr2line.resolve_stack_trace(vmlinux_path, [
    "0xffffffff81234567",
    "0xffffffff81234589",
    "0xffffffff812345ab"
])
# 结果包含：函数名、源文件、行号、源代码上下文
```

---

### 3.4 Agent 层

#### 3.4.1 analyzer.py - AI 分析器

**职责**: 使用 Qwen-Max 大模型进行智能 crash 分析

**核心类**:
```python
class CrashAnalyzer:
    def __init__(self)
    async def analyze(self, context: Dict[str, Any]) -> Dict[str, Any]
    async def find_similar_issues(self, context, historical_issues) -> List[Dict[str, Any]]
    async def generate_report(self, context, analysis_result) -> str
```

**分析流程**:
1. 根据 crash 类型选择对应的提示词模板
2. 调用 Qwen-Max API 进行初步分析
3. 调用 API 生成修复建议
4. 对 crash 进行分类
5. 生成最终报告

**API 调用配置**:
```python
{
    "model": "qwen-max",
    "input": {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    },
    "parameters": {
        "max_tokens": 4096,
        "temperature": 0.3,
        "result_format": "message"
    }
}
```

**输出格式**:
```python
{
    "analysis": "详细分析...",
    "root_cause": "根本原因...",
    "affected_code_path": "代码路径...",
    "similar_issues": ["相似问题1", "相似问题2"],
    "fix_suggestion": "修复建议...",
    "detailed_fix_suggestion": "详细修复建议...",
    "severity": "Critical|High|Medium|Low",
    "confidence": "High|Medium|Low",
    "classification": {
        "classification": "NULL_POINTER|USE_AFTER_FREE|...",
        "original_type": "NULL Pointer Dereference"
    }
}
```

#### 3.4.2 prompt_templates.py - 提示词模板

**职责**: 提供针对不同 crash 类型的专门化提示词模板

**系统提示词**:
```python
def crash_analysis_system_prompt():
    return """You are an expert Linux kernel crash analyst with deep knowledge of:
- Linux kernel internals and architecture
- Memory management and virtual memory
- Process scheduling and synchronization
- Device drivers and kernel modules
- ARM64 and x86_64 architecture specifics
- Common kernel crash patterns and their causes

Your task is to analyze kernel crash reports and provide:
1. Root cause analysis
2. Affected code paths
3. Similar issue patterns
4. Fix suggestions and recommendations

Be thorough but concise. Focus on actionable insights."""
```

**专用模板**:
| 方法 | 适用场景 |
|-----|---------|
| `null_pointer_analysis_prompt` | NULL Pointer Dereference |
| `watchdog_analysis_prompt` | Watchdog Timeout / Lockup |
| `oops_analysis_prompt` | Kernel Oops |
| `crash_classification_prompt` | Crash 分类 |
| `fix_suggestion_prompt` | 修复建议生成 |
| `similar_issue_detection_prompt` | 相似问题检测 |
| `report_generation_prompt` | 报告生成 |

---

### 3.5 Integration 层

#### 3.5.1 jira/client.py - Jira API 客户端

**职责**: 封装 Jira REST API 交互

**核心类**:
```python
@dataclass
class JiraIssueData:
    key: str
    summary: str
    description: str
    issue_type: str
    status: str
    priority: str
    assignee: Optional[str]
    reporter: Optional[str]
    labels: List[str]
    components: List[str]

@dataclass
class JiraAttachmentInfo:
    id: str
    filename: str
    content_type: str
    size: int
    url: str

class JiraClient:
    async def get_issue(self, issue_key) -> Optional[JiraIssueData]
    async def update_issue(self, issue_key, fields) -> bool
    async def add_comment(self, issue_key, comment) -> bool
    async def add_label(self, issue_key, label) -> bool
    async def get_attachments(self, issue_key) -> List[JiraAttachmentInfo]
    async def download_attachment(self, attachment, download_dir) -> Optional[str]
    async def search_issues(self, jql, max_results=50) -> List[Dict]
    async def transition_issue(self, issue_key, transition_id, comment=None) -> bool
```

**认证方式**: Basic Auth (Base64 编码的用户名:API Token)

**ADF (Atlassian Document Format) 支持**:
- 自动处理描述字段的 ADF 格式
- 评论支持 ADF 和普通文本

#### 3.5.2 mcp/memory_client.py - Memory MCP 客户端

**职责**: 集成 Memory MCP，实现分析上下文的持久化和相似问题检索

**核心类**:
```python
class ContextBlock:
    def __init__(self, block_id, block_type, content, metadata=None)
    def to_dict(self) -> Dict[str, Any]

class MemoryMCPClient:
    async def register_context(self, issue_key, context) -> bool
    async def retrieve_similar(self, crash_signature, crash_type, limit=5) -> List[Dict]
    async def get_analysis_history(self, issue_key) -> List[Dict]
    async def store_analysis_result(self, issue_key, analysis_result) -> bool
    async def find_related_issues(self, context) -> List[Dict[str, Any]]
    def _calculate_similarity(self, context1, context2) -> float
    async def cleanup_old_blocks(self, days=90) -> bool
```

**Context Block 结构**:
```python
{
    "block_id": "ke-analysis-PROJ-123",
    "block_type": "kernel_crash_analysis",
    "content": {
        "issue_key": "PROJ-123",
        "crash_type": "NULL Pointer Dereference",
        "crash_location": "function_name+0x123",
        "crash_signature": "hash_of_stack_trace",
        "stack_trace": [...],
        "affected_modules": [...],
        "fault_address": "0x0",
        "process_info": {...}
    },
    "metadata": {
        "source": "ke-analyzer",
        "timestamp": "2026-02-03T10:30:00",
        "version": "1.0"
    }
}
```

**相似度计算**:
| 匹配项 | 权重 |
|-------|------|
| 相同 crash 类型 | 0.3 |
| 相同 crash 位置 | 0.4 |
| 相似调用栈 | 0.3 (每帧 0.1) |
| 相同模块 | 0.2 (每模块 0.1) |

---

## 4. 数据流分析

### 4.1 完整分析流程

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           完整分析数据流                                     │
└────────────────────────────────────────────────────────────────────────────┘

  1. 触发阶段
  ┌─────────────┐
  │ Jira Issue  │ ──创建/更新──▶
  │  (KE类型)   │
  └─────────────┘
         │
         ▼
  ┌─────────────────┐     ┌─────────────────┐
  │  Jira Webhook   │────▶│  POST /webhook  │
  │    Payload      │     │     /jira       │
  └─────────────────┘     └─────────────────┘
                                   │
                                   ▼
  2. 任务创建阶段
  ┌─────────────────────────────────────────────┐
  │ JiraWebhookHandler.handle_issue_created()   │
  │ • 验证 KE 类型                              │
  │ • 提取附件信息                              │
  │ • 生成 task_id                              │
  │ • 创建 AnalysisTask                         │
  └─────────────────────────────────────────────┘
                                   │
                                   ▼
  ┌─────────────────────────────────────────────┐
  │ state_manager.create_task()                 │
  │ • 状态: PENDING                             │
  │ • 持久化到 state.json                       │
  └─────────────────────────────────────────────┘
                                   │
                                   ▼
  3. 后台分析阶段
  ┌─────────────────────────────────────────────┐
  │ run_analysis_pipeline() (BackgroundTasks)   │
  └─────────────────────────────────────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           ▼                       ▼                       ▼
  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
  │  3.1 下载附件   │    │ 3.2 信息提取    │    │  3.3 AI 分析    │
  │                 │    │                 │    │                 │
  │ JiraClient.     │───▶│ vmcore_parser   │───▶│ CrashAnalyzer.  │
  │ download_       │    │ log_parser      │    │ analyze()       │
  │ attachment()    │    │ context_builder │    │                 │
  │                 │    │                 │    │ • 根因分析      │
  │ 状态: DOWNLOAD  │    │ 状态: EXTRACT   │    │ • 修复建议      │
  │                 │    │                 │    │ • 分类          │
  └─────────────────┘    └─────────────────┘    └─────────────────┘
                                                          │
           ┌──────────────────────────────────────────────┘
           ▼
  ┌─────────────────────────────────────────────┐
  │  3.4 结果处理                               │
  │                                             │
  │ • MemoryMCPClient.register_context()        │
  │ • MemoryMCPClient.store_analysis_result()   │
  │ • JiraClient.add_comment()                  │
  │                                             │
  │ 状态: COMPLETED                             │
  └─────────────────────────────────────────────┘
```

### 4.2 Context 数据流

```
┌─────────────────────────────────────────────────────────────────┐
│                       Context 构建流程                          │
└─────────────────────────────────────────────────────────────────┘

Jira Issue
    │
    ├──▶ issue_summary ────────┐
    ├──▶ issue_description ────┤
    └──▶ attachments ──────────┤
                               │
                               ▼
                    ┌──────────────────┐
                    │ ContextBuilder   │
                    │     .build()     │
                    └────────┬─────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │ vmcore_parser│   │ log_parser   │   │ Memory MCP   │
 │              │   │              │   │              │
 │ 调用栈        │   │ Crash 类型   │   │ 历史相似     │
 │ 寄存器        │   │ 错误信息     │   │ 问题检索     │
 │ 模块          │   │ 关键日志     │   │              │
 └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                           ▼
                ┌──────────────────┐
                │  AnalysisContext │
                │                  │
                │ • issue_info     │
                │ • crash_analysis │
                │ • call_stack     │
                │ • modules        │
                │ • registers      │
                │ • context_blocks │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │  CrashAnalyzer   │
                │    .analyze()    │
                └──────────────────┘
```

---

## 5. 配置管理

### 5.1 配置项说明

#### 5.1.1 服务配置 (`orchestrator/config.py`)

```python
class Settings(BaseSettings):
    # 服务配置
    APP_NAME: str = "ke-analyzer"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # FastAPI 配置
    HOST: str = "0.0.0.0"
    PORT: int = 8000
```

#### 5.1.2 Jira 配置

| 配置项 | 环境变量 | 说明 |
|-------|---------|------|
| Jira URL | `JIRA_URL` | Jira 服务器地址 |
| 用户名 | `JIRA_USERNAME` | Jira 登录邮箱 |
| API Token | `JIRA_API_TOKEN` | Jira API Token |
| 项目 Key | `JIRA_PROJECT_KEY` | 默认项目 (可选) |

#### 5.1.3 AI 配置

| 配置项 | 环境变量 | 默认值 | 说明 |
|-------|---------|-------|------|
| 模型 | `AI_MODEL` | `qwen-max` | AI 模型名称 |
| API Key | `AI_API_KEY` | - | DashScope API Key |
| Base URL | `AI_BASE_URL` | - | API 基础地址 |
| Max Tokens | `AI_MAX_TOKENS` | 4096 | 最大生成 token |
| Temperature | `AI_TEMPERATURE` | 0.3 | 温度参数 |

#### 5.1.4 Memory MCP 配置

| 配置项 | 环境变量 | 说明 |
|-------|---------|------|
| MCP URL | `MEMORY_MCP_URL` | Memory MCP 服务地址 |
| MCP Token | `MEMORY_MCP_TOKEN` | API Token |

#### 5.1.5 工具路径配置

| 配置项 | 环境变量 | 默认值 | 说明 |
|-------|---------|-------|------|
| crash | `CRASH_PATH` | `/usr/bin/crash` | crash 工具路径 |
| gdb | `GDB_PATH` | `/usr/bin/gdb` | gdb 路径 |
| addr2line | `ADDR2LINE_PATH` | `/usr/bin/addr2line` | addr2line 路径 |

#### 5.1.6 工作目录配置

| 配置项 | 环境变量 | 默认值 | 说明 |
|-------|---------|-------|------|
| 工作目录 | `WORK_DIR` | `/tmp/ke-analyzer` | 文件存储目录 |
| 最大文件 | `MAX_FILE_SIZE` | 10GB | 附件大小限制 |

### 5.2 配置文件示例

```bash
# .env 文件

# === 服务配置 ===
DEBUG=false
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO

# === Jira 配置 (必需) ===
JIRA_URL=https://your-jira.atlassian.net
JIRA_USERNAME=your-email@example.com
JIRA_API_TOKEN=your-api-token

# === AI 配置 (必需) ===
QWEN_API_KEY=your-dashscope-api-key
QWEN_MODEL=qwen-max
QWEN_MAX_TOKENS=4096
QWEN_TEMPERATURE=0.3

# === Memory MCP (可选) ===
MEMORY_MCP_URL=http://memory-mcp:8080
MEMORY_MCP_API_KEY=your-mcp-api-key
ENABLE_MEMORY_MCP=true

# === 工具配置 ===
CRASH_COMMAND=/usr/bin/crash
GDB_COMMAND=/usr/bin/gdb
ADDR2LINE_COMMAND=/usr/bin/addr2line

# === 存储配置 ===
TEMP_DIR=/tmp/ke-analyzer
MAX_ATTACHMENT_SIZE=10737418240  # 10GB

# === 内核源码 (可选) ===
KERNEL_SOURCE_PATH=/path/to/kernel/sources
KERNEL_SYMBOL_PATH=/path/to/symbols
```

---

## 6. 部署与运维

### 6.1 Docker 部署

```bash
# 构建镜像
docker build -t ke-analyzer:latest .

# 运行容器
docker run -d \
  -p 8000:8000 \
  --env-file .env \
  -v ke-analyzer-data:/tmp/ke-analyzer \
  --name ke-analyzer \
  ke-analyzer:latest
```

### 6.2 Docker Compose 部署

```yaml
version: '3.8'

services:
  ke-analyzer:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    volumes:
      - ke-analyzer-data:/tmp/ke-analyzer
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  ke-analyzer-data:
```

### 6.3 Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ke-analyzer
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ke-analyzer
  template:
    metadata:
      labels:
        app: ke-analyzer
    spec:
      containers:
      - name: ke-analyzer
        image: ke-analyzer:latest
        ports:
        - containerPort: 8000
        envFrom:
        - secretRef:
            name: ke-analyzer-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: ke-analyzer
spec:
  selector:
    app: ke-analyzer
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

### 6.4 监控与日志

**健康检查**:
```bash
curl http://localhost:8000/health
# {"status": "healthy"}
```

**日志级别**:
- `DEBUG`: 调试信息
- `INFO`: 正常运行信息
- `WARNING`: 警告信息
- `ERROR`: 错误信息

**关键日志标记**:
```
INFO - Created task {task_id} for issue {issue_key}
INFO - Downloaded {filename} to {path}
INFO - AI analysis completed for {issue_key}
ERROR - Failed to handle issue created event: {error}
```

### 6.5 故障排查

| 问题 | 可能原因 | 解决方案 |
|-----|---------|---------|
| crash 工具不可用 | 未安装 crash | `apt-get install crash` |
| AI 分析失败 | API Key 错误 | 检查 `QWEN_API_KEY` |
| Webhook 未触发 | URL 不可访问 | 检查网络/firewall |
| 附件下载失败 | Token 权限不足 | 检查 Jira API Token 权限 |
| 状态丢失 | 工作目录未持久化 | 挂载持久化卷 |

---

## 7. 扩展开发指南

### 7.1 添加新的 Crash 类型支持

1. **在 `log_parser.py` 中添加检测模式**:
```python
CRASH_PATTERNS = {
    # ... 现有类型
    CrashType.NEW_TYPE: [
        r'pattern1',
        r'pattern2',
    ],
}
```

2. **在 `prompt_templates.py` 中添加分析模板**:
```python
@staticmethod
def new_type_analysis_prompt(context: Dict[str, Any]) -> str:
    return f"""Analyze this new type crash:
    ...
    """
```

3. **更新 `get_prompt_for_crash_type` 方法**:
```python
def get_prompt_for_crash_type(crash_type: str, context: Dict[str, Any]) -> str:
    if "NEW_TYPE" in crash_type.upper():
        return PromptTemplates.new_type_analysis_prompt(context)
    # ... 其他类型
```

### 7.2 添加新的工具支持

1. **在 `tools/` 目录创建新的工具网关**:
```python
# tools/new_tool.py
class NewToolGateway:
    def __init__(self, cmd="new_tool", default_timeout=60):
        self.cmd = cmd
        self.default_timeout = default_timeout
    
    async def execute(self, ...) -> ToolResult:
        # 实现工具调用逻辑
        pass
```

2. **在 `__init__.py` 中导出**:
```python
from .new_tool import NewToolGateway
__all__ = ['NewToolGateway', ...]
```

3. **在解析器中使用**:
```python
from tools import NewToolGateway

class VmcoredParser:
    def __init__(self):
        self.new_tool = NewToolGateway()
```

### 7.3 添加新的 AI 模型支持

1. **在 `agent/analyzer.py` 中添加新的 API 调用方法**:
```python
async def _call_new_api(self, prompt: str, ...) -> str:
    """Call new AI API."""
    session = await self._get_session()
    headers = {...}
    payload = {...}
    # 实现 API 调用
```

2. **在 `analyze` 方法中添加模型选择逻辑**:
```python
if self.settings.AI_MODEL == "new-model":
    analysis_response = await self._call_new_api(...)
else:
    analysis_response = await self._call_qwen_api(...)
```

### 7.4 项目结构规范

```
ke-analyzer/
├── orchestrator/          # 主控层
│   ├── __init__.py
│   ├── main.py           # 服务入口
│   ├── config.py         # 配置管理
│   ├── state_manager.py  # 状态管理
│   ├── jira_handler.py   # Webhook处理
│   └── pipeline.py       # 分析流程 (可选)
├── extractor/            # 信息提取层
│   ├── __init__.py
│   ├── vmcore_parser.py
│   ├── log_parser.py
│   └── context_builder.py
├── tools/                # 工具网关层
│   ├── __init__.py
│   ├── crash_tool.py
│   ├── gdb_tool.py
│   └── addr2line_tool.py
├── agent/                # AI分析层
│   ├── __init__.py
│   ├── analyzer.py
│   └── prompt_templates.py
├── jira/                 # Jira集成
│   ├── __init__.py
│   └── client.py
├── mcp/                  # Memory MCP
│   ├── __init__.py
│   └── memory_client.py
├── tests/                # 测试
│   └── ...
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── README.md
```

### 7.5 代码规范

- **命名规范**: 使用 snake_case
- **类型注解**: 所有函数参数和返回值添加类型注解
- **文档字符串**: 使用 Google 风格的 docstring
- **错误处理**: 使用 try-except 捕获异常，记录日志
- **异步编程**: 所有 IO 操作使用 async/await

---

## 附录

### A. 术语表

| 术语 | 英文 | 说明 |
|-----|------|------|
| KE | Kernel Exception/Crash | 内核异常/崩溃 |
| vmcore | VM Core Dump | 虚拟机核心转储 |
| vmlinux | vmlinux | 未压缩的内核镜像 |
| MCP | Model Context Protocol | 模型上下文协议 |
| ADF | Atlassian Document Format | Jira 文档格式 |

### B. 参考资料

- [Linux Crash 工具文档](https://crash-utility.github.io/)
- [Qwen-Max API 文档](https://help.aliyun.com/document_detail/611472.html)
- [Jira REST API 文档](https://developer.atlassian.com/cloud/jira/platform/rest/v2/)
- [FastAPI 文档](https://fastapi.tiangolo.com/)

### C. 变更记录

| 版本 | 日期 | 变更内容 |
|-----|------|---------|
| 1.0 | 2026-02-03 | 初始版本 |

---

*文档结束*
