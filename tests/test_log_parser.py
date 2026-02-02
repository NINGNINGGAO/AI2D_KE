"""
Tests for Log Parser
"""

import pytest
import tempfile
import os
from extractor.log_parser import KernelLogParser, KernelCrashEvent


class TestKernelLogParser:
    """Test kernel log parsing."""
    
    @pytest.fixture
    def parser(self):
        return KernelLogParser()
    
    def test_null_pointer_detection(self, parser):
        """Test NULL pointer detection."""
        log_content = """
[   12.345678] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[   12.345679] Mem abort info:
[   12.345680]   ESR = 0x96000004
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            events = parser.parse_file(temp_path)
            assert len(events) > 0
            assert events[0].crash_type == "NULL_POINTER"
        finally:
            os.unlink(temp_path)
    
    def test_oops_detection(self, parser):
        """Test Oops detection."""
        log_content = """
[  123.456789] Internal error: Oops: 96000004 [#1] PREEMPT SMP
[  123.456790] Modules linked in: module1 module2
[  123.456791] CPU: 0 PID: 1234 Comm: test_process
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            events = parser.parse_file(temp_path)
            assert len(events) > 0
            assert events[0].crash_type == "OOPS"
        finally:
            os.unlink(temp_path)
    
    def test_stack_trace_extraction(self, parser):
        """Test stack trace extraction."""
        log_content = """
[  123.456789] Internal error: Oops: 96000004 [#1] PREEMPT SMP
[  123.456790] CPU: 0 PID: 1234 Comm: test_process
[  123.456791] pstate: 60400005 (nZCv daif +PAN -UAO)
[  123.456792] pc : faulty_function+0x24/0x50
[  123.456793] lr : caller_function+0x48/0x80
[  123.456794] sp : ffff800012345678
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            events = parser.parse_file(temp_path)
            assert len(events) > 0
            # Should have detected some stack frames
        finally:
            os.unlink(temp_path)
