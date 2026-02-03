"""
Tools Gateway Package

Provides unified interfaces for kernel debugging tools.
"""

from .crash_tool import CrashToolGateway, CrashCommandResult
from .gdb_tool import GDBToolGateway, GDBResult
from .addr2line_tool import Addr2LineToolGateway, Addr2LineResult
from .asm_analyzer import (
    AssemblyAnalyzer,
    AsmInstruction,
    RegisterState,
    FunctionAsmAnalysis,
    AnomalyType,
    InstructionType,
    analyze_crash_with_assembly
)
from .source_analyzer import (
    KernelSourceInterface,
    KernelSourceAnalyzerStub,
    SourceAnalyzerConfig,
    SourceLocation,
    SymbolInfo,
    CodeContext,
    VariableAccess,
    FunctionAnalysis,
    SymbolType,
    SourceAccessStatus,
    create_source_analyzer,
    get_source_analyzer,
    reset_source_analyzer
)

__all__ = [
    # Crash tool
    'CrashToolGateway',
    'CrashCommandResult',
    # GDB tool
    'GDBToolGateway',
    'GDBResult',
    # Addr2line tool
    'Addr2LineToolGateway',
    'Addr2LineResult',
    # Assembly analyzer
    'AssemblyAnalyzer',
    'AsmInstruction',
    'RegisterState',
    'FunctionAsmAnalysis',
    'AnomalyType',
    'InstructionType',
    'analyze_crash_with_assembly',
    # Source analyzer (kernel source code interface)
    'KernelSourceInterface',
    'KernelSourceAnalyzerStub',
    'SourceAnalyzerConfig',
    'SourceLocation',
    'SymbolInfo',
    'CodeContext',
    'VariableAccess',
    'FunctionAnalysis',
    'SymbolType',
    'SourceAccessStatus',
    'create_source_analyzer',
    'get_source_analyzer',
    'reset_source_analyzer',
]

# 兼容性别名
CrashTool = CrashToolGateway
GDBTool = GDBToolGateway
Addr2LineTool = Addr2LineToolGateway
SourceAnalyzer = KernelSourceInterface
SourceAnalyzerStub = KernelSourceAnalyzerStub
