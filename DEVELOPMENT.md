# KE Analyzer Development Guide

## Development Setup

### Prerequisites

- Python 3.10+
- Docker (optional)
- Git

### Local Development

```bash
# Clone repository
git clone <repo-url>
cd ke-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env
# Edit .env with your settings

# Run in development mode
python -m uvicorn orchestrator.main:app --reload --log-level debug
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_orchestrator.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run with watch mode
ptw tests/
```

### Code Quality

```bash
# Format code with black
black orchestrator/ extractor/ tools/ agent/ jira/ mcp/

# Check with flake8
flake8 orchestrator/ extractor/ tools/ agent/ jira/ mcp/

# Type checking
mypy orchestrator/ extractor/ tools/ agent/ jira/ mcp/

# Run all checks
black --check . && flake8 . && mypy .
```

## Architecture Overview

### Component Interactions

1. **Orchestrator** receives Jira webhook
2. **JiraHandler** validates and parses the webhook
3. **StateManager** creates analysis state
4. **ContextBuilder** extracts crash context
5. **ToolGateway** (crash/gdb/addr2line) provides low-level analysis
6. **CrashAnalyzer** (AI) performs intelligent analysis
7. **JiraClient** updates the issue with results

### Adding New Crash Types

To add support for a new crash type:

1. Update `orchestrator/config.py` - add to `CRASH_TYPES`
2. Update `extractor/log_parser.py` - add detection patterns
3. Add specialized prompt in `agent/prompt_templates.py`

### Adding New Tools

To add a new analysis tool:

1. Create tool wrapper in `tools/`
2. Integrate with `extractor/context_builder.py`
3. Update documentation

## Debugging

### Enable Debug Logging

Set in `.env`:
```
DEBUG=true
LOG_LEVEL=debug
```

### Check Analysis State

```bash
# List all states
curl http://localhost:8000/api/v1/analyses

# Get specific analysis
curl http://localhost:8000/api/v1/analysis/PROJ-123
```

### Manual Tool Testing

```python
# Test crash tool
from tools.crash_tool import CrashToolGateway
import asyncio

gateway = CrashToolGateway()
result = asyncio.run(gateway.get_backtrace("/path/to/vmcore"))
print(result.get_output())
```

## Deployment Checklist

- [ ] Configure all environment variables
- [ ] Test Jira webhook connectivity
- [ ] Verify AI API access
- [ ] Test attachment download
- [ ] Verify crash/gdb tools work
- [ ] Set up monitoring/alerting
- [ ] Configure backup for state files

## Troubleshooting

### Webhook Not Receiving

1. Check firewall rules
2. Verify webhook URL is accessible
3. Check Jira webhook logs

### AI Analysis Failing

1. Verify Qwen API key
2. Check network connectivity to DashScope
3. Review rate limits

### Crash Tool Not Working

1. Verify crash utility is installed
2. Check vmlinux matches vmcore
3. Test manually: `crash vmlinux vmcore`
