"""
Addr2Line Tool Gateway - Convert addresses to source file and line numbers
"""

import subprocess
import asyncio
import logging
import os
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Addr2LineResult:
    """Result of addr2line conversion."""
    address: str
    function: str
    file: str
    line: int
    success: bool
    raw_output: str = ""


class Addr2LineToolGateway:
    """Gateway for addr2line utility to resolve addresses to source locations."""
    
    def __init__(
        self,
        addr2line_cmd: str = "addr2line",
        default_timeout: int = 30
    ):
        self.addr2line_cmd = addr2line_cmd
        self.default_timeout = default_timeout
    
    async def resolve(
        self,
        executable: str,
        address: str,
        use_inline: bool = True,
        use_function: bool = True
    ) -> Addr2LineResult:
        """Resolve a single address to source location."""
        
        if not os.path.exists(executable):
            return Addr2LineResult(
                address=address,
                function="",
                file="",
                line=0,
                success=False,
                raw_output=f"Executable not found: {executable}"
            )
        
        # Validate address format
        address = self._normalize_address(address)
        
        # Build command
        args = [self.addr2line_cmd]
        if use_inline:
            args.append("-i")  # Show inlined functions
        if use_function:
            args.append("-f")  # Show function names
        args.append("-C")  # Demangle C++ symbols
        args.append("-e")
        args.append(executable)
        args.append(address)
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=self.default_timeout
                )
            )
            
            output = result.stdout.strip()
            
            # Check if resolution failed (returns ??:0 or ??:?)
            if "??" in output or result.returncode != 0:
                return Addr2LineResult(
                    address=address,
                    function="",
                    file="",
                    line=0,
                    success=False,
                    raw_output=output
                )
            
            # Parse output
            function, file_line = self._parse_output(output)
            file_path, line_num = self._parse_file_line(file_line)
            
            return Addr2LineResult(
                address=address,
                function=function,
                file=file_path,
                line=line_num,
                success=True,
                raw_output=output
            )
            
        except subprocess.TimeoutExpired:
            return Addr2LineResult(
                address=address,
                function="",
                file="",
                line=0,
                success=False,
                raw_output="Timeout"
            )
        except Exception as e:
            logger.error(f"Addr2Line failed for {address}: {e}")
            return Addr2LineResult(
                address=address,
                function="",
                file="",
                line=0,
                success=False,
                raw_output=str(e)
            )
    
    async def resolve_multiple(
        self,
        executable: str,
        addresses: List[str],
        use_inline: bool = True,
        use_function: bool = True
    ) -> List[Addr2LineResult]:
        """Resolve multiple addresses in batch."""
        results = []
        
        if not os.path.exists(executable):
            for addr in addresses:
                results.append(Addr2LineResult(
                    address=addr,
                    function="",
                    file="",
                    line=0,
                    success=False,
                    raw_output=f"Executable not found: {executable}"
                ))
            return results
        
        # Normalize addresses
        addresses = [self._normalize_address(addr) for addr in addresses]
        
        # Build command with multiple addresses
        args = [self.addr2line_cmd]
        if use_inline:
            args.append("-i")
        if use_function:
            args.append("-f")
        args.append("-C")
        args.extend(["-e", executable])
        args.extend(addresses)
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=self.default_timeout * len(addresses)
                )
            )
            
            output = result.stdout.strip()
            lines = output.split('\n')
            
            # Parse results (function name and file:line pairs)
            for i, addr in enumerate(addresses):
                idx = i * 2
                if idx + 1 < len(lines):
                    function = lines[idx].strip()
                    file_line = lines[idx + 1].strip()
                    file_path, line_num = self._parse_file_line(file_line)
                    
                    success = "??" not in file_line
                    results.append(Addr2LineResult(
                        address=addr,
                        function=function,
                        file=file_path,
                        line=line_num,
                        success=success,
                        raw_output=f"{function}\n{file_line}"
                    ))
                else:
                    results.append(Addr2LineResult(
                        address=addr,
                        function="",
                        file="",
                        line=0,
                        success=False,
                        raw_output="Incomplete output"
                    ))
            
            return results
            
        except Exception as e:
            logger.error(f"Batch addr2line failed: {e}")
            # Return failed results for all
            return [Addr2LineResult(
                address=addr,
                function="",
                file="",
                line=0,
                success=False,
                raw_output=str(e)
            ) for addr in addresses]
    
    async def resolve_stack_trace(
        self,
        executable: str,
        stack_trace: List[str]
    ) -> List[Dict[str, Any]]:
        """Resolve all addresses in a stack trace."""
        # Extract addresses from stack trace lines
        addresses = []
        frame_info = []
        
        for frame in stack_trace:
            addr = self._extract_address(frame)
            if addr:
                addresses.append(addr)
                frame_info.append(frame)
        
        if not addresses:
            return []
        
        # Resolve all addresses
        results = await self.resolve_multiple(executable, addresses)
        
        # Combine with original frame info
        resolved = []
        for i, result in enumerate(results):
            resolved.append({
                "original_frame": frame_info[i] if i < len(frame_info) else "",
                "address": result.address,
                "function": result.function,
                "file": result.file,
                "line": result.line,
                "success": result.success
            })
        
        return resolved
    
    def _normalize_address(self, address: str) -> str:
        """Normalize address format."""
        # Remove any prefixes and whitespace
        address = address.strip()
        
        # Ensure 0x prefix
        if not address.startswith('0x') and not address.startswith('0X'):
            # Check if it's already hex
            if all(c in '0123456789abcdefABCDEF' for c in address):
                address = '0x' + address
        
        return address
    
    def _extract_address(self, text: str) -> Optional[str]:
        """Extract hex address from text."""
        # Pattern: 0xXXXXXXXX or XXXXXXXX
        match = re.search(r'(0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,16}\b)', text)
        if match:
            return self._normalize_address(match.group(1))
        return None
    
    def _parse_output(self, output: str) -> Tuple[str, str]:
        """Parse addr2line output."""
        lines = output.strip().split('\n')
        if len(lines) >= 2:
            return lines[0].strip(), lines[1].strip()
        elif len(lines) == 1:
            return lines[0].strip(), ""
        return "", ""
    
    def _parse_file_line(self, file_line: str) -> Tuple[str, int]:
        """Parse file path and line number."""
        # Format: /path/to/file.c:123 or /path/to/file.c:?
        match = re.match(r'(.+):(\d+|\?)', file_line)
        if match:
            file_path = match.group(1)
            line_str = match.group(2)
            try:
                line_num = int(line_str)
            except ValueError:
                line_num = 0
            return file_path, line_num
        
        return file_line, 0
    
    async def get_source_context(
        self,
        executable: str,
        address: str,
        context_lines: int = 5
    ) -> Dict[str, Any]:
        """Get source code context for an address."""
        result = await self.resolve(executable, address)
        
        if not result.success or not result.file:
            return {
                "address": address,
                "resolved": False,
                "source_available": False,
                "context": ""
            }
        
        # Try to read source file
        source_context = ""
        if os.path.exists(result.file):
            try:
                with open(result.file, 'r') as f:
                    lines = f.readlines()
                
                # Extract context around the line
                start = max(0, result.line - context_lines - 1)
                end = min(len(lines), result.line + context_lines)
                
                context_lines_list = []
                for i in range(start, end):
                    marker = ">>> " if i == result.line - 1 else "    "
                    context_lines_list.append(f"{marker}{i+1:4d}: {lines[i]}")
                
                source_context = ''.join(context_lines_list)
                
            except Exception as e:
                source_context = f"Error reading source: {e}"
        else:
            source_context = f"Source file not found: {result.file}"
        
        return {
            "address": address,
            "resolved": True,
            "function": result.function,
            "file": result.file,
            "line": result.line,
            "source_available": os.path.exists(result.file),
            "context": source_context
        }
    
    def extract_addresses_from_text(self, text: str) -> List[str]:
        """Extract all hex addresses from text."""
        # Pattern for hex addresses
        pattern = r'0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,16}\b'
        matches = re.findall(pattern, text)
        
        # Normalize and deduplicate
        addresses = []
        seen = set()
        for addr in matches:
            normalized = self._normalize_address(addr)
            if normalized not in seen:
                addresses.append(normalized)
                seen.add(normalized)
        
        return addresses
