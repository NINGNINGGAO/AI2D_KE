"""
Source Code Analyzer Interface - 内核源码分析接口

预留接口用于未来接入 Android Linux 内核源码，实现：
- 源码与汇编的联合分析
- 变量/结构体定义查询
- 代码路径静态分析
- 与 crash dump 的关联分析

当前状态：接口预留，待接入完整内核源码后实现
"""

import os
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class SourceAccessStatus(Enum):
    """源码访问状态"""
    NOT_CONFIGURED = "not_configured"      # 未配置源码路径
    CONFIGURED = "configured"              # 已配置但未验证
    AVAILABLE = "available"                # 可用
    PARTIAL = "partial"                    # 部分可用（某些子系统缺失）
    ERROR = "error"                        # 错误或不可访问


class SymbolType(Enum):
    """符号类型"""
    FUNCTION = "function"
    VARIABLE = "variable"
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    MACRO = "macro"
    TYPEDEF = "typedef"
    UNKNOWN = "unknown"


@dataclass
class SourceLocation:
    """源码位置信息"""
    file_path: str
    line_number: int
    column: Optional[int] = None
    function_name: Optional[str] = None
    
    def __str__(self) -> str:
        if self.function_name:
            return f"{self.file_path}:{self.line_number} ({self.function_name})"
        return f"{self.file_path}:{self.line_number}"


@dataclass
class SymbolInfo:
    """符号信息"""
    name: str
    symbol_type: SymbolType
    location: SourceLocation
    size: Optional[int] = None
    type_info: Optional[str] = None  # 对于变量：类型；对于函数：返回类型
    signature: Optional[str] = None   # 对于函数：完整签名
    documentation: Optional[str] = None
    references: List[SourceLocation] = field(default_factory=list)
    
    # Crash 相关信息
    crash_addresses: List[str] = field(default_factory=list)  # 该符号涉及的 crash 地址
    related_issues: List[str] = field(default_factory=list)   # 相关的 issue keys


@dataclass
class CodeContext:
    """代码上下文"""
    before_lines: List[str] = field(default_factory=list)  # 前N行代码
    target_line: str = ""                                    # 目标行
    after_lines: List[str] = field(default_factory=list)   # 后N行代码
    
    def to_string(self, marker: str = ">>>") -> str:
        """转为带标记的字符串"""
        lines = []
        for line in self.before_lines:
            lines.append(f"     {line}")
        lines.append(f"{marker}  {self.target_line}")
        for line in self.after_lines:
            lines.append(f"     {line}")
        return "\n".join(lines)


@dataclass
class VariableAccess:
    """变量访问信息"""
    variable_name: str
    access_type: str  # "read", "write", "address_of"
    location: SourceLocation
    instruction_address: Optional[str] = None  # 汇编地址
    register: Optional[str] = None             # 使用的寄存器


@dataclass
class FunctionAnalysis:
    """函数分析结果"""
    function_name: str
    location: SourceLocation
    
    # 代码结构
    total_lines: int = 0
    complexity_score: Optional[int] = None     # 圈复杂度
    
    # 关键操作
    memory_allocations: List[SourceLocation] = field(default_factory=list)
    memory_deallocations: List[SourceLocation] = field(default_factory=list)
    lock_operations: List[SourceLocation] = field(default_factory=list)
    null_checks: List[SourceLocation] = field(default_factory=list)
    
    # 调用关系
    calls_functions: List[str] = field(default_factory=list)
    called_by_functions: List[str] = field(default_factory=list)
    
    # Crash 相关信息
    crash_history: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)


class KernelSourceInterface(ABC):
    """
    内核源码分析接口（抽象基类）
    
    实现此接口以接入具体的源码分析后端，如：
    - 基于 cscope/gtags 的实现
    - 基于 clang/llvm 的静态分析实现
    - 基于 LSP (Language Server Protocol) 的实现
    - 基于代码索引数据库的实现
    """
    
    @abstractmethod
    async def initialize(self, kernel_source_path: str) -> bool:
        """
        初始化源码分析器
        
        Args:
            kernel_source_path: 内核源码根目录路径
            
        Returns:
            是否初始化成功
        """
        pass
    
    @abstractmethod
    async def get_status(self) -> SourceAccessStatus:
        """获取源码访问状态"""
        pass
    
    @abstractmethod
    async def lookup_symbol(self, symbol_name: str) -> Optional[SymbolInfo]:
        """
        查找符号定义
        
        Args:
            symbol_name: 符号名称
            
        Returns:
            符号信息或 None
        """
        pass
    
    @abstractmethod
    async def lookup_address(self, address: str, vmlinux_path: str) -> Optional[SourceLocation]:
        """
        将地址映射到源码位置
        
        Args:
            address: 十六进制地址 (如 "0xffffffe91b368dac")
            vmlinux_path: vmlinux 文件路径
            
        Returns:
            源码位置或 None
        """
        pass
    
    @abstractmethod
    async def get_source_context(
        self,
        location: SourceLocation,
        context_lines: int = 10
    ) -> Optional[CodeContext]:
        """
        获取指定位置的源代码上下文
        
        Args:
            location: 源码位置
            context_lines: 上下文行数
            
        Returns:
            代码上下文或 None
        """
        pass
    
    @abstractmethod
    async def analyze_function(self, function_name: str) -> Optional[FunctionAnalysis]:
        """
        分析指定函数的代码结构和特征
        
        Args:
            function_name: 函数名
            
        Returns:
            函数分析结果或 None
        """
        pass
    
    @abstractmethod
    async def find_symbol_references(
        self,
        symbol_name: str,
        reference_type: Optional[str] = None
    ) -> List[SourceLocation]:
        """
        查找符号的所有引用位置
        
        Args:
            symbol_name: 符号名称
            reference_type: 引用类型过滤 ("call", "read", "write", "address_of")
            
        Returns:
            引用位置列表
        """
        pass
    
    @abstractmethod
    async def get_structure_layout(
        self,
        struct_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        获取结构体的内存布局信息
        
        Args:
            struct_name: 结构体名称
            
        Returns:
            {
                "name": "struct_name",
                "size": 128,
                "fields": [
                    {"name": "field1", "type": "int", "offset": 0, "size": 4},
                    {"name": "field2", "type": "void*", "offset": 8, "size": 8},
                ]
            }
        """
        pass
    
    @abstractmethod
    async def cross_reference_crash_point(
        self,
        crash_address: str,
        vmlinux_path: str,
        call_stack: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        交叉分析 crash 点和源码
        
        Args:
            crash_address: 崩溃地址
            vmlinux_path: vmlinux 路径
            call_stack: 调用栈
            
        Returns:
            {
                "crash_source_location": SourceLocation,
                "crash_instruction_context": CodeContext,
                "calling_context": List[SourceLocation],
                "relevant_variables": List[VariableAccess],
                "analysis_notes": List[str]
            }
        """
        pass


class KernelSourceAnalyzerStub(KernelSourceInterface):
    """
    内核源码分析器桩实现（预留接口）
    
    当前功能：
    - 记录所有调用请求
    - 返回占位符数据
    - 提供接口文档
    
    未来替换为真实实现：
    - KernelSourceAnalyzerCscope (基于 cscope)
    - KernelSourceAnalyzerClang (基于 clang/libclang)
    - KernelSourceAnalyzerLSP (基于 LSP)
    """
    
    def __init__(self):
        self.source_path: Optional[str] = None
        self.status = SourceAccessStatus.NOT_CONFIGURED
        self._call_log: List[Dict[str, Any]] = []
    
    async def initialize(self, kernel_source_path: str) -> bool:
        """初始化 - 桩实现"""
        self._log_call("initialize", {"kernel_source_path": kernel_source_path})
        
        if not os.path.exists(kernel_source_path):
            logger.warning(f"Kernel source path not found: {kernel_source_path}")
            self.status = SourceAccessStatus.ERROR
            return False
        
        self.source_path = kernel_source_path
        self.status = SourceAccessStatus.CONFIGURED
        
        logger.info(f"KernelSourceAnalyzerStub initialized with path: {kernel_source_path}")
        logger.info("NOTE: This is a stub implementation. Full source analysis not available.")
        
        return True
    
    async def get_status(self) -> SourceAccessStatus:
        """获取状态 - 桩实现"""
        self._log_call("get_status", {})
        return self.status
    
    async def lookup_symbol(self, symbol_name: str) -> Optional[SymbolInfo]:
        """查找符号 - 桩实现"""
        self._log_call("lookup_symbol", {"symbol_name": symbol_name})
        
        # 返回占位符数据，展示接口契约
        return SymbolInfo(
            name=symbol_name,
            symbol_type=SymbolType.UNKNOWN,
            location=SourceLocation(
                file_path=f"{self.source_path or '/path/to/kernel'}/kernel/workqueue.c",
                line_number=1437,
                function_name=symbol_name if '(' not in symbol_name else None
            ),
            documentation="[Source analysis not implemented - stub return]"
        )
    
    async def lookup_address(self, address: str, vmlinux_path: str) -> Optional[SourceLocation]:
        """地址查找 - 桩实现"""
        self._log_call("lookup_address", {"address": address, "vmlinux_path": vmlinux_path})
        
        return SourceLocation(
            file_path=f"{self.source_path or '/path/to/kernel'}/kernel/workqueue.c",
            line_number=1437,
            function_name="__queue_work"
        )
    
    async def get_source_context(
        self,
        location: SourceLocation,
        context_lines: int = 10
    ) -> Optional[CodeContext]:
        """获取源码上下文 - 桩实现"""
        self._log_call("get_source_context", {
            "location": str(location),
            "context_lines": context_lines
        })
        
        # 返回示例上下文
        return CodeContext(
            before_lines=[
                f"/* Line {location.line_number - 2}: Previous code */",
                f"/* Line {location.line_number - 1}: Previous code */",
            ],
            target_line=f"/* Line {location.line_number}: [Source not available - stub] */",
            after_lines=[
                f"/* Line {location.line_number + 1}: Next code */",
                f"/* Line {location.line_number + 2}: Next code */",
            ]
        )
    
    async def analyze_function(self, function_name: str) -> Optional[FunctionAnalysis]:
        """函数分析 - 桩实现"""
        self._log_call("analyze_function", {"function_name": function_name})
        
        return FunctionAnalysis(
            function_name=function_name,
            location=SourceLocation(
                file_path=f"{self.source_path or '/path/to/kernel'}/kernel/workqueue.c",
                line_number=1400,
                function_name=function_name
            ),
            total_lines=150,
            suspicious_patterns=["[Stub: No real analysis performed]"]
        )
    
    async def find_symbol_references(
        self,
        symbol_name: str,
        reference_type: Optional[str] = None
    ) -> List[SourceLocation]:
        """查找引用 - 桩实现"""
        self._log_call("find_symbol_references", {
            "symbol_name": symbol_name,
            "reference_type": reference_type
        })
        
        return [
            SourceLocation(
                file_path=f"{self.source_path or '/path/to/kernel'}/kernel/workqueue.c",
                line_number=1500,
            ),
            SourceLocation(
                file_path=f"{self.source_path or '/path/to/kernel'}/kernel/timer.c",
                line_number=300,
            ),
        ]
    
    async def get_structure_layout(self, struct_name: str) -> Optional[Dict[str, Any]]:
        """获取结构体布局 - 桩实现"""
        self._log_call("get_structure_layout", {"struct_name": struct_name})
        
        return {
            "name": struct_name,
            "size": 128,
            "fields": [
                {"name": "[field1]", "type": "int", "offset": 0, "size": 4},
                {"name": "[field2]", "type": "void*", "offset": 8, "size": 8},
            ],
            "note": "[Stub implementation - not real data]"
        }
    
    async def cross_reference_crash_point(
        self,
        crash_address: str,
        vmlinux_path: str,
        call_stack: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """交叉分析 - 桩实现"""
        self._log_call("cross_reference_crash_point", {
            "crash_address": crash_address,
            "vmlinux_path": vmlinux_path,
            "call_stack_count": len(call_stack)
        })
        
        crash_location = SourceLocation(
            file_path=f"{self.source_path or '/path/to/kernel'}/kernel/workqueue.c",
            line_number=1437,
            function_name="__queue_work"
        )
        
        return {
            "crash_source_location": crash_location,
            "crash_instruction_context": await self.get_source_context(crash_location),
            "calling_context": [
                SourceLocation(
                    file_path=f"{self.source_path}/kernel/workqueue.c",
                    line_number=1642,
                    function_name="delayed_work_timer_fn"
                )
            ],
            "relevant_variables": [
                VariableAccess(
                    variable_name="work",
                    access_type="read",
                    location=crash_location,
                    instruction_address=crash_address,
                    register="X1"
                )
            ],
            "analysis_notes": [
                "[Stub implementation - full source analysis not available]",
                "[Future: Will show actual variable accesses and code paths]",
                "[Future: Will correlate assembly instructions with source lines]"
            ]
        }
    
    def _log_call(self, method: str, params: Dict[str, Any]):
        """记录方法调用"""
        import time
        self._call_log.append({
            "timestamp": time.time(),
            "method": method,
            "params": params
        })
    
    def get_call_log(self) -> List[Dict[str, Any]]:
        """获取调用日志（用于调试和接口验证）"""
        return self._call_log.copy()
    
    def clear_call_log(self):
        """清空调用日志"""
        self._call_log.clear()


# 便捷函数和类型别名
SourceAnalyzer = KernelSourceInterface
SourceAnalyzerStub = KernelSourceAnalyzerStub


async def create_source_analyzer(kernel_source_path: Optional[str] = None) -> KernelSourceInterface:
    """
    创建源码分析器实例
    
    Args:
        kernel_source_path: 内核源码路径（可选）
        
    Returns:
        源码分析器实例（当前返回桩实现）
    """
    analyzer = KernelSourceAnalyzerStub()
    
    if kernel_source_path:
        await analyzer.initialize(kernel_source_path)
    
    return analyzer


# 配置管理
class SourceAnalyzerConfig:
    """源码分析器配置"""
    
    def __init__(self):
        self.kernel_source_path: Optional[str] = None
        self.index_database_path: Optional[str] = None
        self.backend_type: str = "stub"  # future: "cscope", "clang", "lsp"
        self.enable_cache: bool = True
        self.cache_ttl: int = 3600  # seconds
    
    @classmethod
    def from_settings(cls) -> "SourceAnalyzerConfig":
        """从应用配置加载"""
        from orchestrator.config import get_settings
        settings = get_settings()
        
        config = cls()
        config.kernel_source_path = getattr(settings, 'KERNEL_SOURCE_PATH', None)
        config.index_database_path = getattr(settings, 'KERNEL_INDEX_DB_PATH', None)
        config.backend_type = getattr(settings, 'SOURCE_ANALYZER_BACKEND', 'stub')
        
        return config


# 全局实例（单例模式）
_source_analyzer_instance: Optional[KernelSourceInterface] = None


async def get_source_analyzer() -> KernelSourceInterface:
    """获取全局源码分析器实例"""
    global _source_analyzer_instance
    
    if _source_analyzer_instance is None:
        config = SourceAnalyzerConfig.from_settings()
        _source_analyzer_instance = await create_source_analyzer(
            config.kernel_source_path
        )
    
    return _source_analyzer_instance


async def reset_source_analyzer():
    """重置全局实例（用于测试或重新配置）"""
    global _source_analyzer_instance
    _source_analyzer_instance = None
