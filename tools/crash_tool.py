"""
Crash Tool Gateway - Wrapper for crash utility commands
Provides unified interface for crash dump analysis.
"""

import subprocess
import asyncio
import logging
import tempfile
import os
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CrashCommandResult:
    """Result of a crash command execution."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    success: bool
    execution_time: float = 0.0
    
    def get_output(self) -> str:
        """Get combined output."""
        return self.stdout + self.stderr if self.stderr else self.stdout


class CrashToolGateway:
    """Gateway for crash utility with caching and error handling."""
    
    def __init__(
        self,
        crash_cmd: str = "crash",
        default_timeout: int = 300,
        cache_enabled: bool = True
    ):
        self.crash_cmd = crash_cmd
        self.default_timeout = default_timeout
        self.cache_enabled = cache_enabled
        self._cache: Dict[str, CrashCommandResult] = {}
        self._active_sessions: Dict[str, Tuple[str, str]] = {}  # issue_key -> (vmcore, vmlinux)
    
    def _get_cache_key(self, vmcore: str, command: str) -> str:
        """Generate cache key for a command."""
        import hashlib
        key_data = f"{vmcore}:{command}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def execute(
        self,
        vmcore_path: str,
        command: str,
        vmlinux_path: Optional[str] = None,
        timeout: Optional[int] = None,
        use_cache: bool = True
    ) -> CrashCommandResult:
        """Execute a crash command."""
        
        # Check cache
        if use_cache and self.cache_enabled:
            cache_key = self._get_cache_key(vmcore_path, command)
            if cache_key in self._cache:
                logger.debug(f"Cache hit for command: {command}")
                return self._cache[cache_key]
        
        # Validate paths
        if not os.path.exists(vmcore_path):
            return CrashCommandResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=f"VMCORE not found: {vmcore_path}",
                success=False
            )
        
        if vmlinux_path and not os.path.exists(vmlinux_path):
            return CrashCommandResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=f"VMLINUX not found: {vmlinux_path}",
                success=False
            )
        
        timeout = timeout or self.default_timeout
        
        # Build command arguments
        args = [self.crash_cmd]
        if vmlinux_path:
            args.append(vmlinux_path)
        args.append(vmcore_path)
        
        # Create command script
        script_content = f"{command}\nquit\n"
        
        import time
        start_time = time.time()
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crash', delete=False) as f:
                f.write(script_content)
                script_path = f.name
            
            args.extend(["-i", script_path])
            
            logger.info(f"Executing crash command: {command}")
            
            # Run in executor to not block
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            )
            
            execution_time = time.time() - start_time
            
            cmd_result = CrashCommandResult(
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                success=result.returncode == 0,
                execution_time=execution_time
            )
            
            # Cache result
            if use_cache and self.cache_enabled:
                cache_key = self._get_cache_key(vmcore_path, command)
                self._cache[cache_key] = cmd_result
            
            logger.info(f"Crash command completed in {execution_time:.2f}s")
            return cmd_result
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            logger.error(f"Crash command timed out after {timeout}s")
            return CrashCommandResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                success=False,
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Crash command failed: {e}")
            return CrashCommandResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=str(e),
                success=False,
                execution_time=execution_time
            )
        finally:
            if 'script_path' in locals() and os.path.exists(script_path):
                os.unlink(script_path)
    
    async def get_backtrace(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None,
        all_cpus: bool = True
    ) -> CrashCommandResult:
        """Get backtrace from crash dump."""
        command = "bt -a" if all_cpus else "bt"
        return await self.execute(vmcore_path, command, vmlinux_path)
    
    async def get_sys_info(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get system information from crash dump."""
        return await self.execute(vmcore_path, "sys", vmlinux_path)
    
    async def get_ps_list(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get process list from crash dump."""
        return await self.execute(vmcore_path, "ps", vmlinux_path)
    
    async def get_modules(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get loaded modules from crash dump."""
        return await self.execute(vmcore_path, "mod", vmlinux_path)
    
    async def get_vm_info(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get virtual memory information."""
        return await self.execute(vmcore_path, "vm", vmlinux_path)
    
    async def get_symbol_info(
        self,
        vmcore_path: str,
        address: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get symbol information for an address."""
        return await self.execute(vmcore_path, f"sym {address}", vmlinux_path)
    
    async def get_log(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get kernel log from crash dump."""
        return await self.execute(vmcore_path, "log", vmlinux_path)
    
    async def get_dmesg(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get dmesg from crash dump."""
        return await self.execute(vmcore_path, "dmesg", vmlinux_path)
    
    async def get_files(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get open files information."""
        return await self.execute(vmcore_path, "files", vmlinux_path)
    
    async def get_net(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get network information."""
        return await self.execute(vmcore_path, "net", vmlinux_path)
    
    async def get_dev(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get device information."""
        return await self.execute(vmcore_path, "dev", vmlinux_path)
    
    async def get_irq(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get IRQ information."""
        return await self.execute(vmcore_path, "irq", vmlinux_path)
    
    async def get_mount_info(
        self,
        vmcore_path: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get mount information."""
        return await self.execute(vmcore_path, "mount", vmlinux_path)
    
    async def get_task_info(
        self,
        vmcore_path: str,
        task_addr: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get specific task information."""
        return await self.execute(vmcore_path, f"task {task_addr}", vmlinux_path)
    
    async def get_pte(
        self,
        vmcore_path: str,
        address: str,
        vmlinux_path: Optional[str] = None
    ) -> CrashCommandResult:
        """Get page table entry."""
        return await self.execute(vmcore_path, f"pte {address}", vmlinux_path)
    
    def clear_cache(self):
        """Clear command cache."""
        self._cache.clear()
        logger.info("Crash tool cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cache_enabled": self.cache_enabled,
            "cached_entries": len(self._cache),
            "active_sessions": len(self._active_sessions)
        }
