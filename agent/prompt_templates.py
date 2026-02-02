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
