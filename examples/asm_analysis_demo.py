"""
Assembly Analysis Example - 汇编层次分析示例

展示如何使用新的汇编分析功能来分析 kernel crash。
"""

import asyncio
import logging
from tools.asm_analyzer import AssemblyAnalyzer, analyze_crash_with_assembly

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# 示例：用户提供的 crash 案例
EXAMPLE_ASM_OUTPUT = """
   0xffffffe91b368dac <__queue_work+40>:    ldrb    w8, [x1, #258]
   0xffffffe91b368db0 <__queue_work+44>:    tbz     w8, #0, 0xffffffe91b368e28
   0xffffffe91b368db4 <__queue_work+48>:    ldr     x8, [x0, #8]
   0xffffffe91b368db8 <__queue_work+52>:    ldr     x9, [x0]
   0xffffffe91b368dbc <__queue_work+56>:    cmp     x8, x9
   0xffffffe91b368dc0 <__queue_work+60>:    b.ne    0xffffffe91b368e28
   0xffffffe91b368dc4 <__queue_work+64>:    mov     w8, #0x1                    
   0xffffffe91b368dc8 <__queue_work+68>:    bfi     w8, w3, #1, #1
   0xffffffe91b368dcc <__queue_work+72>:    strb    w8, [x0, #16]
   0xffffffe91b368dd0 <__queue_work+76>:    ldr     x8, [x0, #8]
=> 0xffffffe91b368dd4 <__queue_work+80>:    ldr     x9, [x8, #48]
   0xffffffe91b368dd8 <__queue_work+84>:    str     x8, [x9, #8]
   0xffffffe91b368ddc <__queue_work+88>:    str     x9, [x8]
   0xffffffe91b368de0 <__queue_work+92>:    ldr     x9, [x0, #8]
   0xffffffe91b368de4 <__queue_work+96>:    add     x10, x0, #0x18
"""

EXAMPLE_REGISTERS = {
    'x0': '0000000000000000',
    'x1': '0000000000000000',
    'x2': 'FFFFFF80D12F7A80',
    'x3': '0000000000000001',
    'x4': '0000000000000080',
    'x5': '0000000000000000',
    'x6': '0000000000000000',
    'x7': '0000000000000001',
    'x8': '0000000000000000',
    'x9': '0000000100000102',
    'x10': '00000001441AA743',
    'x11': '00000001041AA744',
    'x12': 'FFFFFF81D8E8AEA8',
    'x13': '0000000000000040',
    'x14': 'FFFFFF81D8E8AEB0',
    'x15': 'FFFFFFFFFFFFFFFF',
    'x16': '0000000000000000',
    'x17': '00000001041AA744',
    'x18': 'FFFFFFC00801D050',
    'x19': '0000000000000102',
    'x20': 'FFFFFFE91CA36CE8',
    'x21': 'FFFFFF80D12F7AB0',
    'x22': 'FFFFFF80036C5C80',
    'x23': '00000000000000E0',
    'x24': 'FFFFFF80036C5C80',
    'x25': '0000000000000001',
    'x26': 'FFFFFFE91D956008',
    'x27': 'FFFFFFE91D989DD8',
    'x28': 'FFFFFFE91DB1F758',
    'x29': 'FFFFFFC00801BD00',
    'x30': 'FFFFFFE91B36D188',
    'sp': 'FFFFFFC00801BCF0',
    'pc': 'FFFFFFE91B368DAC',
}

EXAMPLE_CRASH_PC = '0xFFFFFFE91B368DAC'


async def demo_basic_analysis():
    """演示基本汇编分析"""
    logger.info("=" * 60)
    logger.info("Demo 1: Basic Assembly Analysis")
    logger.info("=" * 60)
    
    # 使用便捷函数进行分析
    report = analyze_crash_with_assembly(
        asm_output=EXAMPLE_ASM_OUTPUT,
        registers=EXAMPLE_REGISTERS,
        crashed_address=EXAMPLE_CRASH_PC,
        function_name='__queue_work'
    )
    
    print("\n📊 Assembly Analysis Report:")
    print(f"  Function: {report['function']}")
    print(f"  Instructions Analyzed: {report['instruction_count']}")
    print(f"  Suspicious Instructions: {report['suspicious_instruction_count']}")
    
    if report['key_findings']:
        print("\n🔍 Key Findings:")
        for finding in report['key_findings']:
            print(f"  • {finding}")
    
    if report['anomalies']:
        print("\n⚠️  Detected Anomalies:")
        for anomaly in report['anomalies']:
            print(f"  [{anomaly['severity']}] {anomaly['type']}")
            print(f"    {anomaly['description']}")
    
    if report['recommendations']:
        print("\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")


async def demo_bitflip_detection():
    """演示位翻转检测"""
    logger.info("\n" + "=" * 60)
    logger.info("Demo 2: Bitflip Detection")
    logger.info("=" * 60)
    
    analyzer = AssemblyAnalyzer()
    
    # 测试不同的值
    test_values = [
        0x0000000000000000,  # NULL
        0x0000000000000001,  # 可能是 0x0 的第 0 位翻转
        0x0000000000000002,  # 可能是 0x0 的第 1 位翻转
        0x0000000100000000,  # 可能是 0x0 的第 32 位翻转
        0xFFFFFF80D12F7A80,  # 正常的内核地址
    ]
    
    print("\n🔍 Bitflip Detection Results:")
    for value in test_values:
        result = analyzer.detect_bitflip(value, expected_range=(0xFFFFFF0000000000, 0xFFFFFFFFFFFFFFFF))
        
        if result and result['detected']:
            print(f"\n  Value: {value:#x}")
            print(f"    ⚠️  Possible bitflip detected!")
            print(f"    Flipped value: {result['flipped_value']}")
            print(f"    Bit position: {result['bit_position']}")
            print(f"    Confidence: {result['confidence']}")
        else:
            print(f"\n  Value: {value:#x} - No bitflip pattern detected")


async def demo_register_tracking():
    """演示寄存器跟踪分析"""
    logger.info("\n" + "=" * 60)
    logger.info("Demo 3: Register State Tracking")
    logger.info("=" * 60)
    
    from tools.asm_analyzer import RegisterState
    
    print("\n📋 Register Analysis:")
    
    # 分析关键寄存器
    key_registers = ['x0', 'x1', 'x8', 'x19']
    
    for reg_name in key_registers:
        if reg_name in EXAMPLE_REGISTERS:
            reg_state = RegisterState(
                name=reg_name,
                value=EXAMPLE_REGISTERS[reg_name]
            )
            
            print(f"\n  {reg_name.upper()}: {reg_state.value}")
            print(f"    Value (int): {reg_state.value_int:#x}")
            print(f"    Is NULL: {reg_state.is_null}")
            print(f"    Is Suspicious: {reg_state.is_suspicious}")
            if reg_state.suspicious_reason:
                print(f"    Reason: {reg_state.suspicious_reason}")


async def demo_instruction_analysis():
    """演示指令级分析"""
    logger.info("\n" + "=" * 60)
    logger.info("Demo 4: Instruction-Level Analysis")
    logger.info("=" * 60)
    
    from tools.asm_analyzer import AsmInstruction
    
    # 创建一个可疑的指令
    suspicious_inst = AsmInstruction(
        address='0xffffffe91b368dac',
        instruction='ldrb',
        operands='w8, [x1, #258]',
        source_ref='kernel/workqueue.c:1437'
    )
    
    print("\n📜 Instruction Analysis:")
    print(f"  Address: {suspicious_inst.address}")
    print(f"  Instruction: {suspicious_inst.instruction}")
    print(f"  Operands: {suspicious_inst.operands}")
    print(f"  Type: {suspicious_inst.inst_type.value}")
    print(f"  Memory Access: {suspicious_inst.memory_access}")
    print(f"  Address Register: {suspicious_inst.memory_address_reg}")
    print(f"  Offset: {suspicious_inst.memory_offset}")
    print(f"  Read Registers: {suspicious_inst.read_regs}")
    print(f"  Write Registers: {suspicious_inst.write_regs}")


async def demo_full_analysis():
    """演示完整的分析流程"""
    logger.info("\n" + "=" * 60)
    logger.info("Demo 5: Full Crash Analysis with Context")
    logger.info("=" * 60)
    
    analyzer = AssemblyAnalyzer()
    
    # 解析汇编输出
    asm_analysis = analyzer.parse_assembly_output(
        EXAMPLE_ASM_OUTPUT,
        function_name='__queue_work'
    )
    
    # 结合寄存器进行分析
    asm_analysis = analyzer.analyze_with_registers(
        asm_analysis,
        EXAMPLE_REGISTERS,
        EXAMPLE_CRASH_PC
    )
    
    # 生成详细报告
    report = analyzer.generate_analysis_report(asm_analysis)
    
    print("\n📊 Full Analysis Report:")
    print(f"\n{'='*50}")
    print(f"Function: {report['function']}")
    print(f"Function Address: {report['function_address']}")
    print(f"Total Instructions: {report['instruction_count']}")
    print(f"Suspicious Instructions: {report['suspicious_instruction_count']}")
    
    print(f"\n{'='*50}")
    print("ANOMALIES:")
    print(f"{'='*50}")
    if report['anomalies']:
        for i, anomaly in enumerate(report['anomalies'], 1):
            print(f"\n{i}. [{anomaly['severity']}] {anomaly['type']}")
            print(f"   Address: {anomaly['address']}")
            print(f"   Instruction: {anomaly['instruction']}")
            print(f"   Description: {anomaly['description']}")
    else:
        print("  No anomalies detected")
    
    print(f"\n{'='*50}")
    print("KEY FINDINGS:")
    print(f"{'='*50}")
    for finding in report['key_findings']:
        print(f"  • {finding}")
    
    print(f"\n{'='*50}")
    print("RECOMMENDATIONS:")
    print(f"{'='*50}")
    for rec in report['recommendations']:
        print(f"  • {rec}")


async def demo_with_call_stack():
    """演示结合调用栈的分析"""
    logger.info("\n" + "=" * 60)
    logger.info("Demo 6: Analysis with Call Stack")
    logger.info("=" * 60)
    
    # 模拟调用栈
    call_stack = [
        {'function': '__queue_work', 'address': '0xFFFFFFE91B368DAC'},
        {'function': 'delayed_work_timer_fn', 'address': '0xFFFFFFE91B36D178'},
        {'function': 'call_timer_fn', 'address': '0xFFFFFFE91B46570C'},
        {'function': 'expire_timers', 'address': '0xFFFFFFE91B4653DC'},
        {'function': '__run_timers', 'address': '0xFFFFFFE91B465150'},
    ]
    
    print("\n📞 Call Stack Analysis:")
    print(f"{'='*50}")
    
    analyzer = AssemblyAnalyzer()
    
    # 分析调用栈中的函数（实际使用时会获取每个函数的汇编）
    for i, frame in enumerate(call_stack):
        func_name = frame['function']
        func_addr = frame['address']
        
        print(f"\nFrame #{i}: {func_name}")
        print(f"  Address: {func_addr}")
        
        # 这里演示的是如何标记可疑的帧
        if func_name == '__queue_work':
            print("  ⚠️  Crash occurred in this function")
            print("  🔍 Requires deep assembly analysis")
        elif 'timer' in func_name.lower():
            print("  ℹ️  Timer-related function")
            print("  🔍 Check for timer corruption")


async def main():
    """主函数"""
    print("\n" + "=" * 70)
    print("   KE Analyzer - Assembly Level Analysis Demo")
    print("   汇编层次分析功能演示")
    print("=" * 70)
    
    try:
        await demo_basic_analysis()
        await demo_bitflip_detection()
        await demo_register_tracking()
        await demo_instruction_analysis()
        await demo_full_analysis()
        await demo_with_call_stack()
        
        print("\n" + "=" * 70)
        print("   Demo Completed!")
        print("=" * 70)
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
