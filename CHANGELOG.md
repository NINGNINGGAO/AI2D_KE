# Changelog

All notable changes to the KE Analyzer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-02-05

### Added - Panic Overview Enhancement

- **PanicOverviewExtractor** (`extractor/panic_overview.py`)
  - Automatic extraction of crash time and system uptime
  - Kernel version and release information extraction
  - Smart crash scenario analysis (context, process, CPU)
  - Suspected module identification from backtrace
  - Fault address and error code parsing

- **PanicOverview dataclass** with comprehensive fields:
  - Crash time, uptime, kernel version
  - Crash type and subtype classification
  - Process information (name, PID, TID)
  - CPU information (crash CPU, total CPUs)
  - Machine type and platform detection
  - Error details (code, fault address, message)

### Added - Call Stack Deep Analysis

- **CallStackAnalyzer** (`extractor/callstack_analyzer.py`)
  - Function call chain analysis (caller -> callee relationships)
  - Execution context detection (syscall, irq, softirq, workqueue, timer, kthread)
  - Subsystem tracing (memory_management, filesystem, network, block, scheduling, etc.)
  - Suspicious pattern detection:
    - Recursion detection
    - Deep stack detection (>50 frames)
    - Nested IRQ detection
    - Lock contention detection
  - Likely crash scenario inference based on call patterns

- **StackAnalysis dataclass** with:
  - Enhanced call frame information (function type, subsystem, source location)
  - Call chain representation
  - Execution context identification
  - Subsystem trace
  - Suspicious patterns and severity levels
  - Likely crash scenarios

### Added - Register History Tracking

- **AdvancedRegisterAnalyzer** (`extractor/register_analyzer.py`)
  - Current register state analysis with value interpretation
  - Register history tracking through assembly instructions
  - Function argument extraction and analysis
  - Register chain tracing from source to crash point
  - Suspicious register detection:
    - NULL pointer in X0
    - Userspace address in kernel context
    - Stack pointer misalignment
    - NULL return address
  - Root cause function identification

- **RegisterAnalysis dataclass** with:
  - Current register states with type annotations
  - Crash PC, SP, FP, and faulting address
  - Per-frame register states
  - Register change history
  - Suspicious register findings
  - Root cause analysis results

- **Comprehensive report generation** with formatted output

### Enhanced

- **vmcore_parser.py** - Enhanced with new analyzers integration
  - Now calls PanicOverviewExtractor for detailed crash overview
  - Integrates CallStackAnalyzer for deep call stack analysis
  - Integrates AdvancedRegisterAnalyzer for register tracking
  - Returns enhanced analysis results in addition to basic parsing

- **context_builder.py** - Enhanced context building
  - Adds panic_overview extraction
  - Adds stack_analysis extraction  
  - Adds register_analysis extraction
  - Enhanced context blocks with new analysis types
  - New formatting methods for all analysis types

- **prompt_templates.py** - Enhanced AI prompts
  - `enhanced_analysis_prompt()` - Comprehensive analysis using all new analyzers
  - `get_enhanced_prompt_for_context()` - Intelligent prompt selection
  - Structured output format for better AI analysis

- **analyzer.py** - Enhanced AI analysis
  - Uses new enhanced prompts automatically when available
  - Better structured output format

- **pipeline.py** - New file for analysis pipeline orchestration
  - Coordinates complete analysis workflow
  - Integrates all extractors and analyzers
  - Jira comment generation with enhanced analysis results

### Technical Details

#### New Modules
- `extractor/panic_overview.py` (~430 lines)
- `extractor/callstack_analyzer.py` (~520 lines)
- `extractor/register_analyzer.py` (~710 lines)

#### Modified Modules
- `extractor/__init__.py` - Export new analyzers
- `extractor/vmcore_parser.py` - Integration with new analyzers
- `extractor/context_builder.py` - Enhanced context building
- `agent/prompt_templates.py` - Enhanced prompts
- `agent/analyzer.py` - Use enhanced prompts
- `orchestrator/pipeline.py` - New pipeline orchestration

#### Supported Register Analysis (ARM64)
- General purpose: X0-X28
- Frame pointer: X29 (FP)
- Link register: X30 (LR)
- Stack pointer: SP
- Program counter: PC

#### Supported Subsystem Detection
- Memory management (mm/, slab, alloc, free, page)
- Filesystem (fs/, vfs, inode, dentry, ext4, xfs)
- Network (net/, tcp, udp, skbuff)
- Block I/O (block/, bio, request)
- Scheduling (sched, mutex, wait, wake)
- IRQ handling (irq, interrupt)
- Device drivers (pci, usb, i2c)
- Security (selinux, apparmor)
- Virtualization (kvm, hyperv)

## [1.1.0] - 2026-02-03

### Added - Assembly Level Analysis

- **asm_analyzer.py** - Assembly-level deep analysis
  - Register tracking for ARM64 (X0-X30, SP, PC)
  - NULL pointer detection
  - Bit-flip detection for hardware fault identification
  - Memory access pattern analysis
  - Anomaly detection with severity classification

- **gdb_tool.py enhancements**
  - Function disassembly with context
  - Crash point register analysis
  - Backtrace with full context extraction

- **source_analyzer.py (预留)**
  - Interface for kernel source code analysis
  - Stub implementation for future Cscope/Clang/LSP integration

### Enhanced

- AI prompts for assembly-level analysis
- Jira comment format with assembly analysis results
- Context blocks for Memory MCP with assembly data

## [1.0.0] - 2026-02-02

### Initial Release

- **Core System**
  - FastAPI-based webhook server
  - Jira webhook integration (issue created/updated)
  - Task state management
  - Attachment download handling

- **Analysis Pipeline**
  - vmcore parsing using crash tool
  - Kernel log parsing
  - AI analysis using Qwen-Max
  - Report generation and Jira updates

- **Tool Integration**
  - crash command wrapper
  - gdb integration
  - addr2line integration

- **Memory MCP Integration**
  - Context block registration
  - Historical issue retrieval

- **Supported Crash Types**
  - NULL pointer dereference
  - Kernel Oops
  - Kernel Panic
  - Page Fault
  - Watchdog Timeout
  - Soft Lockup
  - Hard Lockup
  - Kernel BUG

---

## Version History Summary

| Version | Date | Key Features |
|---------|------|--------------|
| 1.2.0 | 2026-02-05 | Panic Overview, Call Stack Analysis, Register History |
| 1.1.0 | 2026-02-03 | Assembly Level Analysis, Bit-flip Detection |
| 1.0.0 | 2026-02-02 | Initial Release, Basic Analysis Pipeline |
