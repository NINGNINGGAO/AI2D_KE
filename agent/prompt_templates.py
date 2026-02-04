"""
Prompt Templates for AI Kernel Crash Analysis
"""

from typing import Dict, Any, List


class PromptTemplates:
    """Collection of prompt templates for crash analysis."""
    
    @staticmethod
    def crash_analysis_system_prompt() -> str:
        """System prompt for crash analysis."""
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

    @staticmethod
    def crash_analysis_user_prompt(context: Dict[str, Any]) -> str:
        """User prompt for crash analysis."""
        return f"""Please analyze the following kernel crash report:

=== CRASH INFORMATION ===
Issue: {context.get('issue_key', 'Unknown')}
Crash Type: {context.get('crash_type', 'Unknown')}
Crash Location: {context.get('crash_location', 'Unknown')}
Process: {context.get('process_name', 'Unknown')} (PID: {context.get('pid', 'N/A')})
CPU: {context.get('cpu', 'N/A')}
Fault Address: {context.get('fault_address', 'Unknown')}

=== STACK TRACE ===
{chr(10).join(f"  {i+1}. {frame}" for i, frame in enumerate(context.get('stack_trace', [])))}

=== REGISTERS ===
{chr(10).join(f"  {reg}: {val}" for reg, val in context.get('registers', {}).items())}

=== AFFECTED MODULES ===
{', '.join(context.get('affected_modules', ['Unknown']))}

=== RAW CONTEXT ===
{context.get('raw_crash_info', 'N/A')[:2000]}

Please provide your analysis in the following JSON format:
{{
  "analysis": "Detailed analysis of the crash including what happened and why",
  "root_cause": "Identified root cause with technical explanation",
  "affected_code_path": "Description of the code path involved",
  "similar_issues": ["List of similar known issues or patterns"],
  "fix_suggestion": "Recommended fix or debugging steps",
  "severity": "Critical|High|Medium|Low",
  "confidence": "High|Medium|Low"
}}"""

    @staticmethod
    def null_pointer_analysis_prompt(context: Dict[str, Any]) -> str:
        """Specialized prompt for NULL pointer dereference."""
        return f"""Analyze this NULL pointer dereference crash:

Crash Location: {context.get('crash_location', 'Unknown')}
Fault Address: {context.get('fault_address', '0x0')}
Process: {context.get('process_name', 'Unknown')}

Stack Trace:
{chr(10).join(context.get('stack_trace', []))}

Key questions to answer:
1. Which pointer was NULL and why wasn't it checked?
2. Is this a race condition or initialization issue?
3. What defensive checks should be added?
4. Are there similar unchecked pointers in the same code path?

Provide your findings in structured format with code-level recommendations."""

    @staticmethod
    def watchdog_analysis_prompt(context: Dict[str, Any]) -> str:
        """Specialized prompt for watchdog/lockup analysis."""
        return f"""Analyze this watchdog/lockup crash:

Crash Type: {context.get('crash_type', 'Unknown')}
Process: {context.get('process_name', 'Unknown')}
CPU: {context.get('cpu', 'N/A')}

Stack Trace:
{chr(10).join(context.get('stack_trace', []))}

Key questions to answer:
1. What was the process doing when the lockup occurred?
2. Is there evidence of deadlock or resource contention?
3. Are there spinlocks held for too long?
4. Is there an infinite loop or blocking operation?
5. What are the other CPUs doing at the time?

Provide your findings with focus on synchronization issues."""

    @staticmethod
    def oops_analysis_prompt(context: Dict[str, Any]) -> str:
        """Specialized prompt for kernel oops analysis."""
        return f"""Analyze this kernel oops:

Crash Type: {context.get('crash_type', 'Oops')}
Location: {context.get('crash_location', 'Unknown')}
Process: {context.get('process_name', 'Unknown')}

Stack Trace:
{chr(10).join(context.get('stack_trace', []))}

Registers:
{chr(10).join(f"{k}: {v}" for k, v in context.get('registers', {}).items())}

Key questions to answer:
1. What triggered the oops (memory access, invalid instruction, etc.)?
2. Is there a pattern indicating a specific bug type (use-after-free, buffer overflow, etc.)?
3. What kernel subsystem is primarily involved?
4. Are there any obvious code defects visible in the stack trace?

Provide detailed technical analysis."""

    @staticmethod
    def report_generation_prompt(analysis_result: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Prompt for generating human-readable report."""
        return f"""Generate a professional kernel crash analysis report based on the following:

CRASH SUMMARY:
- Issue: {context.get('issue_key', 'Unknown')}
- Type: {context.get('crash_type', 'Unknown')}
- Location: {context.get('crash_location', 'Unknown')}

AI ANALYSIS:
{analysis_result.get('analysis', 'N/A')}

ROOT CAUSE:
{analysis_result.get('root_cause', 'N/A')}

FIX SUGGESTION:
{analysis_result.get('fix_suggestion', 'N/A')}

Generate a well-formatted report suitable for:
1. Jira issue comments
2. Email communication
3. Technical documentation

Include sections: Summary, Technical Details, Root Cause Analysis, Recommendations, Next Steps.
"""

    @staticmethod
    def similar_issue_detection_prompt(context: Dict[str, Any], historical_issues: List[Dict]) -> str:
        """Prompt for detecting similar historical issues."""
        return f"""Compare the current crash with historical issues to find similarities:

CURRENT CRASH:
- Signature: {context.get('crash_signature', 'Unknown')}
- Type: {context.get('crash_type', 'Unknown')}
- Location: {context.get('crash_location', 'Unknown')}
- Stack Hash: {hash(str(context.get('stack_trace', [])))}

HISTORICAL ISSUES:
{chr(10).join(f"- {issue.get('key')}: {issue.get('summary', '')}" for issue in historical_issues[:10])}

Identify potential duplicates or related issues based on:
1. Crash signature similarity
2. Same crash location
3. Similar stack trace patterns
4. Same affected modules

Return a list of potentially related issue keys with confidence scores."""

    @staticmethod
    def fix_suggestion_prompt(context: Dict[str, Any], analysis: str) -> str:
        """Prompt for generating fix suggestions."""
        return f"""Based on the following crash analysis, provide specific fix suggestions:

CRASH LOCATION: {context.get('crash_location', 'Unknown')}
AFFECTED MODULES: {', '.join(context.get('affected_modules', []))}

ANALYSIS:
{analysis}

Provide:
1. Immediate mitigation steps
2. Code-level fix recommendations with pseudocode
3. Testing suggestions to verify the fix
4. Prevention recommendations (code review, static analysis, etc.)

Be specific and actionable."""

    @staticmethod
    def crash_classification_prompt(context: Dict[str, Any]) -> str:
        """Prompt for classifying crash type."""
        return f"""Classify this kernel crash into one of the following categories:

1. NULL_POINTER - NULL pointer dereference
2. USE_AFTER_FREE - Accessing freed memory
3. BUFFER_OVERFLOW - Buffer overflow/underflow
4. RACE_CONDITION - Race condition/concurrency issue
5. RESOURCE_LEAK - Memory/resource leak leading to crash
6. DRIVER_BUG - Device driver bug
7. MEMORY_CORRUPTION - Memory corruption
8. STACK_OVERFLOW - Kernel stack overflow
9. HARDWARE_ERROR - Hardware-related error
10. CONFIGURATION_ERROR - Kernel configuration issue
11. UNKNOWN - Cannot determine

CRASH DETAILS:
Type: {context.get('crash_type', 'Unknown')}
Location: {context.get('crash_location', 'Unknown')}
Stack Trace:
{chr(10).join(context.get('stack_trace', [])[:5])}

Provide classification with confidence level and reasoning."""

    @staticmethod
    def code_review_prompt(function_name: str, context: Dict[str, Any]) -> str:
        """Prompt for reviewing crash-related code."""
        return f"""Review the function {function_name} where the crash occurred:

CRASH CONTEXT:
- Type: {context.get('crash_type', 'Unknown')}
- Fault Address: {context.get('fault_address', 'Unknown')}
- Stack Trace:
{chr(10).join(context.get('stack_trace', []))}

Perform a code review focusing on:
1. NULL pointer checks
2. Boundary conditions
3. Locking and synchronization
4. Error handling paths
5. Memory allocation/deallocation

Identify potential bugs and suggest improvements."""

    @staticmethod
    def get_prompt_for_crash_type(crash_type: str, context: Dict[str, Any]) -> str:
        """Get appropriate prompt based on crash type."""
        crash_type_upper = crash_type.upper()
        
        if "NULL" in crash_type_upper:
            return PromptTemplates.null_pointer_analysis_prompt(context)
        elif "WATCHDOG" in crash_type_upper or "LOCKUP" in crash_type_upper:
            return PromptTemplates.watchdog_analysis_prompt(context)
        elif "OOPS" in crash_type_upper:
            return PromptTemplates.oops_analysis_prompt(context)
        else:
            return PromptTemplates.crash_analysis_user_prompt(context)

    @staticmethod
    def assembly_level_analysis_prompt(context: Dict[str, Any]) -> str:
        """Assembly-level deep analysis prompt."""
        asm_analysis = context.get('assembly_analysis', {})
        
        prompt = f"""Perform a detailed assembly-level analysis of this kernel crash:

=== CRASH CONTEXT ===
Crash PC: {asm_analysis.get('crash_pc', 'Unknown')}
Crash Type: {context.get('crash_type', 'Unknown')}
Process: {context.get('process_name', 'Unknown')} (PID: {context.get('pid', 'N/A')})
CPU: {context.get('cpu', 'N/A')}

=== REGISTERS AT CRASH ===
{chr(10).join(f"  {reg}: {val}" for reg, val in list(context.get('registers', {}).items())[:20])}

=== ASSEMBLY ANALYSIS RESULTS ===
Anomalies Detected: {asm_analysis.get('anomaly_count', 0)}
Bitflip Detected: {asm_analysis.get('bitflip_detected', False)}
"""
        
        if asm_analysis.get('bitflip_details'):
            bitflip = asm_analysis['bitflip_details']
            prompt += f"""
Bitflip Details:
  - Original Value: {bitflip.get('original_value')}
  - Flipped Value: {bitflip.get('flipped_value')}
  - Bit Position: {bitflip.get('bit_position')}
  - Confidence: {bitflip.get('confidence')}
"""
        
        if asm_analysis.get('anomalies'):
            prompt += "\n=== DETECTED ANOMALIES ===\n"
            for i, anomaly in enumerate(asm_analysis['anomalies'][:5], 1):
                prompt += f"""
{i}. [{anomaly.get('severity')}] {anomaly.get('type')}
   Description: {anomaly.get('description', 'N/A')}
   Function: {anomaly.get('function', 'N/A')}
"""
        
        if asm_analysis.get('suspicious_patterns'):
            prompt += "\n=== SUSPICIOUS PATTERNS ===\n"
            for pattern in asm_analysis['suspicious_patterns'][:3]:
                prompt += f"  - {pattern.get('function')}: {pattern.get('finding')}\n"
        
        prompt += f"""
=== CALL STACK ===
{chr(10).join(f"  {i}. {frame.get('function', 'unknown')}" for i, frame in enumerate(context.get('call_stack', [])[:10]))}

=== ANALYSIS TASKS ===
Based on the assembly-level information provided, please analyze:

1. **Root Cause at Instruction Level**:
   - Which specific instruction caused the crash?
   - What was the exact memory address being accessed?
   - Was it a load or store operation?

2. **Register State Analysis**:
   - Analyze the register values at crash time
   - Identify any suspicious or unexpected values
   - Track how the faulting address was computed

3. **Bitflip/Memory Corruption Detection**:
   - Could this be caused by a bitflip? (check bitflip detection results)
   - Are there signs of memory corruption (unusual addresses, patterns)?
   - Could it be DMA corruption or hardware issues?

4. **Memory Access Pattern**:
   - Was the access through a valid pointer?
   - Was there an offset calculation that went wrong?
   - Was it accessing kernel stack, heap, or device memory?

5. **Code Path Analysis**:
   - Trace how execution reached the crash point
   - Identify any missing boundary checks
   - Check for race conditions or synchronization issues

6. **Fix Recommendations**:
   - Specific code changes needed
   - Defensive programming suggestions
   - Hardware/memory diagnostics if applicable

Please provide your analysis in structured format with technical details."""
        
        return prompt

    @staticmethod
    def memory_corruption_analysis_prompt(context: Dict[str, Any]) -> str:
        """Specialized prompt for memory corruption analysis."""
        return f"""Analyze potential memory corruption in this kernel crash:

=== CRASH INFORMATION ===
Crash Type: {context.get('crash_type', 'Unknown')}
Fault Address: {context.get('fault_address', 'Unknown')}
Crash Location: {context.get('crash_location', 'Unknown')}

=== REGISTERS ===
{chr(10).join(f"  {reg}: {val}" for reg, val in context.get('registers', {}).items())}

=== ASSEMBLY ANALYSIS ===
{context.get('assembly_analysis', {}).get('anomaly_count', 0)} anomalies detected

Key questions to answer:
1. Is the fault address valid kernel memory? (check against typical ranges)
2. Is there evidence of stack corruption? (check SP, FP values)
3. Could this be use-after-free? (check for freed object patterns)
4. Is there heap corruption evidence? (check heap metadata)
5. Could it be a buffer overflow? (check access offsets)
6. Hardware issues: bitflips, DMA corruption, memory controller errors?

Provide detailed technical analysis with evidence from the assembly level."""

    @staticmethod
    def enhanced_analysis_prompt(context: Dict[str, Any]) -> str:
        """Enhanced analysis prompt using new analyzers."""
        panic_overview = context.get('panic_overview', {})
        stack_analysis = context.get('stack_analysis', {})
        register_analysis = context.get('register_analysis', {})
        
        prompt = f"""Perform a comprehensive kernel crash analysis using the following detailed information:

=== PANIC OVERVIEW ===
"""
        
        if panic_overview and 'error' not in panic_overview:
            prompt += f"""Crash Type: {panic_overview.get('crash_type', 'Unknown')}
"""
            if panic_overview.get('crash_subtype'):
                prompt += f"Subtype: {panic_overview['crash_subtype']}\n"
            
            prompt += f"""Process: {panic_overview.get('process_name', 'Unknown')} (PID: {panic_overview.get('pid', 'N/A')})
CPU: {panic_overview.get('cpu_id', 'N/A')}
"""
            if panic_overview.get('kernel_version'):
                prompt += f"Kernel Version: {panic_overview['kernel_version']}\n"
            if panic_overview.get('crash_scenario'):
                prompt += f"Crash Scenario: {panic_overview['crash_scenario']}\n"
            if panic_overview.get('suspected_module'):
                prompt += f"Suspected Module: {panic_overview['suspected_module']}\n"
        else:
            prompt += "Panic overview not available\n"
        
        prompt += f"""
=== CALL STACK ANALYSIS ===
"""
        
        if stack_analysis and 'error' not in stack_analysis:
            prompt += f"""Execution Context: {stack_analysis.get('execution_context', 'Unknown')}
Crash Function: {stack_analysis.get('crash_function', 'Unknown')}
Entry Point: {stack_analysis.get('entry_point', 'Unknown')}
"""
            
            if stack_analysis.get('subsystem_trace'):
                prompt += f"Subsystem Trace: {' -> '.join(stack_analysis['subsystem_trace'])}\n"
            
            if stack_analysis.get('call_chains'):
                prompt += "\nCall Chains:\n"
                for chain in stack_analysis['call_chains'][:5]:
                    prompt += f"  {chain.get('caller', 'unknown')} -> {chain.get('callee', 'unknown')}\n"
            
            if stack_analysis.get('suspicious_patterns'):
                prompt += "\nSuspicious Patterns:\n"
                for pattern in stack_analysis['suspicious_patterns'][:3]:
                    prompt += f"  [{pattern.get('severity', 'low').upper()}] {pattern.get('type')}: {pattern.get('description', '')}\n"
            
            if stack_analysis.get('likely_scenarios'):
                prompt += "\nLikely Scenarios:\n"
                for i, scenario in enumerate(stack_analysis['likely_scenarios'][:3], 1):
                    prompt += f"  {i}. {scenario}\n"
        else:
            prompt += "Stack analysis not available\n"
        
        prompt += f"""
=== REGISTER ANALYSIS ===
"""
        
        if register_analysis and 'error' not in register_analysis:
            if register_analysis.get('crash_pc'):
                prompt += f"Crash PC: {register_analysis['crash_pc']}\n"
            if register_analysis.get('faulting_address'):
                prompt += f"Faulting Address: {register_analysis['faulting_address']}\n"
            
            if register_analysis.get('suspicious_registers'):
                prompt += "\nSuspicious Registers:\n"
                for susp in register_analysis['suspicious_registers'][:5]:
                    prompt += f"  [{susp.get('severity', 'low').upper()}] {susp.get('register')}: {susp.get('issue')}\n"
                    if susp.get('likely_cause'):
                        prompt += f"      Likely Cause: {susp['likely_cause']}\n"
            
            if register_analysis.get('register_chain'):
                prompt += "\nRegister Chain:\n"
                for entry in register_analysis['register_chain'][:5]:
                    if 'register' in entry:
                        mark = "⚠️ " if entry.get('is_suspicious') else "  "
                        prompt += f"  {mark}{entry.get('register')} = {entry.get('value')}\n"
            
            prompt += "\nRoot Cause Analysis:\n"
            if register_analysis.get('likely_fault_source'):
                prompt += f"  Fault Source: {register_analysis['likely_fault_source']}\n"
            if register_analysis.get('root_cause_function'):
                prompt += f"  Suspected Function: {register_analysis['root_cause_function']}\n"
        else:
            prompt += "Register analysis not available\n"
        
        prompt += f"""
=== ANALYSIS TASKS ===

Based on the comprehensive analysis above, please provide:

1. **Executive Summary**:
   - What happened (in 2-3 sentences)
   - When/where it happened
   - Impact severity

2. **Technical Root Cause**:
   - Specific code path analysis
   - Why the crash occurred
   - Which function/module is at fault

3. **Register-Level Analysis**:
   - Which register caused the crash
   - How the faulty value got there
   - Tracing the value through the call stack

4. **Function Call Analysis**:
   - How did execution reach the crash point
   - What was the call chain
   - Any suspicious patterns in the call stack

5. **Fix Recommendations**:
   - Immediate mitigation
   - Code-level fix (with pseudocode if applicable)
   - Testing strategy
   - Prevention measures

6. **Additional Context**:
   - Is this a known pattern?
   - Similar issues to check
   - Hardware considerations (if applicable)

Provide your analysis in structured format. Be specific and technical."""
        
        return prompt

    @staticmethod
    def get_enhanced_prompt_for_context(context: Dict[str, Any]) -> str:
        """Get appropriate enhanced prompt based on available analysis."""
        # 如果有新的分析结果，使用增强版
        if context.get('panic_overview') or context.get('stack_analysis') or context.get('register_analysis'):
            return PromptTemplates.enhanced_analysis_prompt(context)
        
        # 否则使用原有方法
        crash_type = context.get('crash_type', 'Unknown')
        return PromptTemplates.get_prompt_for_crash_type(crash_type, context)
