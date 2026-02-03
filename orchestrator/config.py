"""
配置管理模块
"""
import os
from typing import Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """应用配置"""
    
    # 服务配置
    APP_NAME: str = Field(default="ke-analyzer", description="应用名称")
    APP_VERSION: str = Field(default="1.0.0", description="应用版本")
    DEBUG: bool = Field(default=False, description="调试模式")
    
    # FastAPI 配置
    HOST: str = Field(default="0.0.0.0", description="监听地址")
    PORT: int = Field(default=8000, description="监听端口")
    
    # Jira 配置
    JIRA_URL: str = Field(default="", description="Jira 服务器 URL")
    JIRA_USERNAME: str = Field(default="", description="Jira 用户名")
    JIRA_API_TOKEN: str = Field(default="", description="Jira API Token")
    JIRA_PROJECT_KEY: str = Field(default="", description="Jira 项目 Key")
    
    # AI 配置
    AI_MODEL: str = Field(default="qwen-max", description="AI 模型名称")
    AI_API_KEY: str = Field(default="", description="AI API Key")
    AI_BASE_URL: str = Field(default="", description="AI API Base URL")
    
    # Memory MCP 配置
    MEMORY_MCP_URL: str = Field(default="", description="Memory MCP 服务 URL")
    MEMORY_MCP_TOKEN: str = Field(default="", description="Memory MCP Token")
    
    # 工具路径配置
    CRASH_PATH: str = Field(default="/usr/bin/crash", description="crash 工具路径")
    GDB_PATH: str = Field(default="/usr/bin/gdb", description="gdb 工具路径")
    ADDR2LINE_PATH: str = Field(default="/usr/bin/addr2line", description="addr2line 工具路径")
    
    # 工作目录配置
    WORK_DIR: str = Field(default="/tmp/ke-analyzer", description="工作目录")
    MAX_FILE_SIZE: int = Field(default=10*1024*1024*1024, description="最大文件大小 (10GB)")
    
    # 日志配置
    LOG_LEVEL: str = Field(default="INFO", description="日志级别")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="日志格式"
    )
    
    # 汇编分析配置 (v1.1)
    ENABLE_ASSEMBLY_ANALYSIS: bool = Field(default=True, description="启用汇编层次分析")
    MAX_ASM_CONTEXT_INSTRUCTIONS: int = Field(default=30, description="分析的汇编指令上下文数量")
    BITFLIP_DETECTION_ENABLED: bool = Field(default=True, description="启用位翻转检测")
    
    # 内核源码分析配置 (预留, v1.1+)
    KERNEL_SOURCE_PATH: Optional[str] = Field(default=None, description="内核源码路径")
    KERNEL_INDEX_DB_PATH: Optional[str] = Field(default=None, description="源码索引数据库路径")
    SOURCE_ANALYZER_BACKEND: str = Field(default="stub", description="源码分析后端类型 (stub/cscope/clang/lsp)")
    ENABLE_SOURCE_CACHE: bool = Field(default=True, description="启用源码分析缓存")
    SOURCE_CACHE_TTL: int = Field(default=3600, description="源码分析缓存TTL(秒)")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# 全局配置实例
settings = Settings()


def get_settings() -> Settings:
    """获取配置"""
    return settings
