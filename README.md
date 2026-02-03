# KE Analyzer - Android Kernel Crash Automatic Pre-analysis System

一个用于自动预分析 Android Kernel Crash (KE) 问题的系统，通过 AI 辅助和**汇编层次深度分析**减少 Jira 工单处理负担。

## 🆕 最新功能 (v1.1)

### 汇编层次分析 (Assembly Level Analysis)
- 🔍 **寄存器跟踪分析** - 自动检测 X0-X30、SP、PC 等寄存器的可疑值
- 🎯 **空指针检测** - 识别对 NULL 寄存器的内存访问
- 🔄 **位翻转检测** - 识别硬件故障（RAM/辐射）导致的位翻转
- 🛡️ **内存破坏检测** - 检测越界访问、异常偏移

### 内核源码分析接口 (预留)
- 📚 预留与 Android Linux 内核源码联合分析的接口
- 🔗 未来将支持：源码-汇编联合分析、符号查询、代码路径静态分析

## 系统架构

```
Jira Issue --> Webhook --> Orchestrator
                               │
                 +-------------+-------------+
                 │                           │
           含附件?                      Qwen-Max Agent
                 │                           │
       下载vmlinux/vmcore/kern.log <---- Function Call
                 │                           │
       Context Extractor ----------> Tool Gateway
                 │                     /    |    \
       注册到Memory MCP            crash  gdb  addr2line
                 │                Log Parser  
                 │                           │
                 │              ┌────────────┴────────────┐
                 │              │   asm_analyzer          │
                 │              │   (汇编层次分析)         │
                 │              │   • 寄存器跟踪           │
                 │              │   • 位翻转检测           │
                 │              │   • 异常模式识别         │
                 │              └────────────┬────────────┘
                 │                           │
                 │              ┌────────────┴────────────┐
                 │              │   source_analyzer       │
                 │              │   (源码分析接口-预留)    │
                 │              │   • 符号查询             │
                 │              │   • 地址映射             │
                 │              │   • 交叉引用             │
                 │              └─────────────────────────┘
                 │                           │
                 +-------------> Report Generator
                                       │
                              更新Jira Issue + 评论
```

## 功能特性

### Crash 类型识别
- NULL pointer dereference
- Kernel Oops
- Kernel panic
- Watchdog timeout (Hard/Soft lockup)
- BUG_ON
- Warning
- Segmentation fault

### AI 分析能力
- 自动根本原因分析
- **汇编层次深度分析** (NEW)
- 代码路径推测
- 相似历史问题关联
- 修复建议生成

### 汇编层次分析 (NEW)
| 能力 | 描述 | 应用场景 |
|------|------|---------|
| **寄存器跟踪** | 分析 X0-X30、SP、PC 等寄存器状态 | 识别 NULL 指针、可疑值 |
| **位翻转检测** | 检测单/双位翻转模式 | 硬件故障识别 |
| **内存访问分析** | 分析 LDR/STR 指令的内存访问 | 检测越界、非法访问 |
| **异常模式识别** | 识别常见的 crash 模式 | 自动分类问题 |

## 快速开始

### 环境要求

- Python 3.10+
- Linux 环境（推荐使用 Docker）
- 可选：`crash` 工具（用于解析 vmcore）
- 可选：`gdb` 和 `addr2line`（用于符号解析）
- **可选**：Android Linux 内核源码（用于源码分析，预留功能）

### 安装

#### 方式一：使用 Docker（推荐）

```bash
# 构建镜像
docker build -t ke-analyzer:latest .

# 运行容器
docker run -d \
  -p 8000:8000 \
  -e JIRA_URL=https://your-jira.atlassian.net \
  -e JIRA_USERNAME=your-email@example.com \
  -e JIRA_API_TOKEN=your-api-token \
  -e QWEN_API_KEY=your-qwen-api-key \
  --name ke-analyzer \
  ke-analyzer:latest
```

#### 方式二：本地安装

```bash
# 克隆仓库
git clone <repository>
cd ke-analyzer

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或: venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 配置环境变量（参见配置部分）
cp .env.example .env
# 编辑 .env 文件

# 启动服务
python -m orchestrator.main
```

## 配置

创建 `.env` 文件：

```env
# FastAPI Settings
DEBUG=false
HOST=0.0.0.0
PORT=8000

# Jira Configuration
JIRA_URL=https://your-jira.atlassian.net
JIRA_USERNAME=your-email@example.com
JIRA_API_TOKEN=your-api-token
JIRA_WEBHOOK_SECRET=your-webhook-secret

# Qwen-Max AI Configuration
QWEN_API_KEY=your-dashscope-api-key
QWEN_MODEL=qwen-max
QWEN_MAX_TOKENS=4096
QWEN_TEMPERATURE=0.3

# Memory MCP Configuration (可选)
MEMORY_MCP_URL=http://memory-mcp:8080
MEMORY_MCP_API_KEY=your-mcp-api-key
ENABLE_MEMORY_MCP=true

# Tool Gateway Configuration
CRASH_COMMAND=crash
GDB_COMMAND=gdb
ADDR2LINE_COMMAND=addr2line

# Assembly Analysis Configuration (NEW)
ENABLE_ASSEMBLY_ANALYSIS=true
MAX_ASM_CONTEXT_INSTRUCTIONS=30
BITFLIP_DETECTION_ENABLED=true

# Kernel Source Analysis Configuration (预留)
KERNEL_SOURCE_PATH=/path/to/kernel/sources  # 可选
KERNEL_INDEX_DB_PATH=/data/kernel_index.db  # 可选
SOURCE_ANALYZER_BACKEND=stub  # future: cscope, clang, lsp

# Storage
TEMP_DIR=/tmp/ke-analyzer
MAX_ATTACHMENT_SIZE=524288000

# Analysis Settings
MAX_ANALYSIS_TIME=600
ENABLE_KERNEL_RAG=true
```

## Jira Webhook 配置

### 1. 创建 Webhook

在 Jira 中：
1. 转到 **Settings** → **System** → **Webhooks**
2. 点击 **Create a Webhook**
3. 配置：
   - **Name**: KE Analyzer Webhook
   - **URL**: `http://your-server:8000/webhook/jira`
   - **Events**: Issue created, Issue updated
   - **Issue**: All issues

### 2. 配置自动分析标签

- 添加 `no-auto-analysis` 标签可跳过自动分析
- 添加 `ke-analyzed` 标签表示已分析（防止重复分析）
- 添加 `skip-ke-analysis` 标签可跳过特定问题的分析

## API 使用

### 健康检查

```bash
curl http://localhost:8000/health
```

### 手动触发分析

```bash
curl -X POST http://localhost:8000/api/v1/analysis/PROJ-123/trigger
```

### 查询分析状态

```bash
curl http://localhost:8000/api/v1/analysis/PROJ-123
```

### 查询汇编分析报告 (NEW)

```bash
curl http://localhost:8000/api/v1/analysis/PROJ-123/assembly
```

### 列出所有分析

```bash
curl "http://localhost:8000/api/v1/analyses?active_only=true"
```

### 取消分析

```bash
curl -X DELETE http://localhost:8000/api/v1/analysis/PROJ-123
```

## 开发

### 项目结构

```
ke-analyzer/
├── orchestrator/          # 主控服务
│   ├── main.py           # FastAPI 入口
│   ├── config.py         # 配置管理
│   ├── jira_handler.py   # Jira Webhook 处理
│   ├── state_manager.py  # 分析状态管理
│   └── pipeline.py       # 分析流程 (可选)
├── extractor/            # 信息提取
│   ├── vmcore_parser.py  # vmcore 解析 + 汇编分析集成
│   ├── log_parser.py     # kernel log 解析
│   └── context_builder.py # AI context 构建
├── tools/                # 工具网关
│   ├── crash_tool.py     # crash 命令封装
│   ├── gdb_tool.py       # gdb 封装 + 汇编提取
│   ├── addr2line_tool.py # addr2line 封装
│   ├── asm_analyzer.py   # 🆕 汇编层次分析器
│   └── source_analyzer.py # 🆕 内核源码分析接口 (预留)
├── agent/                # AI 分析
│   ├── analyzer.py       # Qwen-Max 分析逻辑 + 汇编集成
│   └── prompt_templates.py # 提示词模板
├── jira/                 # Jira 集成
│   └── client.py         # Jira API 客户端
├── mcp/                  # Memory MCP
│   └── memory_client.py  # 上下文持久化
├── examples/             # 🆕 示例脚本
│   └── asm_analysis_demo.py  # 汇编分析演示
├── docs/                 # 🆕 文档
│   └── ASSEMBLY_ANALYSIS.md  # 汇编功能详细文档
└── tests/                # 测试
    └── ...
```

### 运行汇编分析演示

```bash
# 运行演示脚本
PYTHONPATH=/path/to/ke-analyzer:$PYTHONPATH python examples/asm_analysis_demo.py
```

### 运行测试

```bash
# 安装测试依赖
pip install -r requirements.txt

# 运行测试
pytest tests/ -v

# 带覆盖率
pytest tests/ --cov=ke_analyzer --cov-report=html
```

### 代码格式化

```bash
# 格式化代码
black orchestrator/ extractor/ tools/ agent/ jira/ mcp/

# 类型检查
mypy orchestrator/ extractor/ tools/ agent/ jira/ mcp/
```

## 部署

### Kubernetes

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
        env:
        - name: JIRA_URL
          valueFrom:
            secretKeyRef:
              name: ke-analyzer-secrets
              key: jira-url
        - name: JIRA_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: ke-analyzer-secrets
              key: jira-token
        - name: ENABLE_ASSEMBLY_ANALYSIS
          value: "true"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
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
```

### Docker Compose

```yaml
version: '3.8'

services:
  ke-analyzer:
    build: .
    ports:
      - "8000:8000"
    environment:
      - JIRA_URL=${JIRA_URL}
      - JIRA_USERNAME=${JIRA_USERNAME}
      - JIRA_API_TOKEN=${JIRA_API_TOKEN}
      - QWEN_API_KEY=${QWEN_API_KEY}
      - ENABLE_ASSEMBLY_ANALYSIS=true
    volumes:
      - ./data:/tmp/ke-analyzer
      # 可选：挂载内核源码
      # - /path/to/kernel/sources:/kernel:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 故障排除

### 常见问题

1. **crash 工具不可用**
   - 确保安装了 `crash` 包
   - 检查 vmlinux 文件与 vmcore 匹配

2. **AI 分析失败**
   - 检查 `QWEN_API_KEY` 是否正确
   - 确认网络可以访问阿里云 DashScope

3. **汇编分析异常**
   - 确保 `gdb` 工具可用
   - 检查 vmlinux 文件包含调试信息
   - 查看日志中的汇编解析错误

4. **Jira Webhook 未触发**
   - 检查 Webhook URL 是否可访问
   - 确认 Webhook Secret 配置正确
   - 查看 Jira 审计日志

5. **附件下载失败**
   - 检查 Jira API Token 权限
   - 确认附件大小未超过限制

### 日志查看

```bash
# Docker 日志
docker logs -f ke-analyzer

# Kubernetes 日志
kubectl logs -f deployment/ke-analyzer

# 查看汇编分析日志
docker logs ke-analyzer | grep -i assembly
```

## 文档

- [技术架构文档](TECHNICAL_DOCUMENTATION.md) - 详细架构设计
- [汇编分析文档](docs/ASSEMBLY_ANALYSIS.md) - 汇编层次分析功能详解
- [升级说明](UPGRADE_SUMMARY.md) - v1.1 升级内容总结
- [API 文档](http://localhost:8000/docs) - Swagger UI (运行后访问)

## 贡献

欢迎提交 Issue 和 Pull Request！

### 未来计划

- [ ] x86/x86_64 架构汇编分析支持
- [ ] 内核源码接入 (Cscope/Clang 后端)
- [ ] 历史数据对比和回归检测
- [ ] 机器学习模型训练用于异常检测
- [ ] 图形化报告展示

## 许可证

MIT License

## 联系方式

如有问题，请联系项目维护者。

---

**注意**: 汇编层次分析功能需要 `gdb` 工具支持。内核源码分析接口目前为预留状态，待接入完整内核源码后启用。
