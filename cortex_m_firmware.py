import idc
import ida_bytes
import ida_funcs
import ida_name
import idaapi

from amnesia import Amnesia

class CortexMFirmware:
    '''
    Filename:       cortex_m_firmware.py
    Description:    IDA Python module for loading ARM Cortex M firmware. 
    Contributors:   tmanning@duo.com
        
    Example IDA commandline usage:
    ------------------------------
    from cortex_m_firmware import *
    cortex = CortexMFirmware(auto=True)
    
    The vtoffset parameter is used by annotate_vector_table():
    ----------------------------------------------------------
    from cortex_m_firmware import *
    cortex = CortexMFirmware()
    cortex.annotate_vector_table()
    cortex.annotate_vector_table(0x10000)
    cortex.find_functions()

    Notes:
    ------
    This code will undergo continued development. Development might break scripts.
    '''
    
    def __init__(self, auto=False):
        '''

        Vector table offset is passed in at instantiation.
        Multiple vector tables can exist in a flash image

        32 is the max number of irqs allowed in M0
        48 items in self.annotations
        
        This class will likely change and potentially break scripts.
        It's probably a good idea to backup your IDB file before trying this out.

        '''

        self.auto = auto

        self.annotations = [
            "arm_initial_sp",
            "arm_reset",
            "arm_nmi",
            "arm_hard_fault",
            "arm_mm_fault",
            "arm_bus_fault",
            "arm_usage_fault",
            "arm_reserved", "arm_reserved", "arm_reserved", "arm_reserved",
            "arm_svcall",
            "arm_reserved_debug", "arm_reserved",
            "arm_pendsv",
            "arm_systick",
            "arm_irq_0", "arm_irq_1", "arm_irq_2", "arm_irq_3",
            "arm_irq_4", "arm_irq_5", "arm_irq_6", "arm_irq_7",
            "arm_irq_8", "arm_irq_9", "arm_irq_10", "arm_irq_11",
            "arm_irq_12", "arm_irq_13", "arm_irq_14", "arm_irq_15",
            "arm_irq_16", "arm_irq_17", "arm_irq_18", "arm_irq_19",
            "arm_irq_20", "arm_irq_21", "arm_irq_22", "arm_irq_23",
            "arm_irq_24", "arm_irq_25", "arm_irq_26", "arm_irq_27",
            "arm_irq_28", "arm_irq_29", "arm_irq_30", "arm_irq_31",
        ]

        if not self.verify_processor_settings():
            print "ERROR: Processor architecture is incorrect"
            print "Please set processor type to ARM, and ARM architecture options to ARMv7-M (or other valid Cortex architecture)"
            return None
            
        
        if self.auto:
            self.annotate_vector_table()
            self.find_functions()

    def verify_processor_settings(self):
        '''
        The intent here is to validate the processor has been set to ARM.
        In a better world, I would be able to check the processor sub options.
        In a perfect world, I could set these myself, or would know the IDA APIs a little better.
        '''
        info = idaapi.get_inf_structure()
        return info.procName=="ARM"

    def annotate_vector_table(self, vtoffset=0x0000000000):
        '''
        Name the vector table entries according to docs:
        http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABIFJFG.html
    
        Vector tables can appear in mulitple places in device flash
        Functions are not renamed because multiple vectors might point to a single function
        Append the address of the VT entry to the name from self.annotations to keep unique names
    
        '''
                
        for annotation_index in range(len(self.annotations)):
            entry_addr = vtoffset + 4 * annotation_index
            entry_name = "%s_%08x" % (self.annotations[annotation_index], entry_addr)
            
            idc.MakeDword(entry_addr)
            ida_name.set_name(entry_addr, entry_name, 0)
        
            # get the bytes of the vt entry
            dword = idc.Dword(entry_addr)

            if dword != 0:
                # print "ea %08x = 0x%08x" % (ea, dword)
                idc.SetRegEx(dword-1, "T", 1, idc.SR_user)
                idc.MakeCode(dword-1)
                idc.MakeFunction(dword-1)
                # TODO fix the offsets created here
                # for thumb, they show to be off by a byte
                # one of the end args controls stuff about this
                idc.OpOffEx(entry_addr,0,idaapi.REF_OFF32, -1, 0, 0)
            
                instruction = idc.Word(dword-1)
                
                # functions like this are common 
                if instruction == 0xe7fe:
                    idc.SetFunctionCmt(dword-1, 'Infinite Loop', 1)


    def find_functions(self):
        '''
        Using the Amnesia IDA Python module, find ARM code and create functions
        '''
        
        a =  Amnesia()
        a.find_pushpop_registers_thumb(makecode=True)
        a.find_pushpop_registers_arm(makecode=True)
        a.find_function_epilogue_bxlr(makecode=True)
        a.make_new_functions_heuristic_push_regs(makefunction=True)
        a.nonfunction_first_instruction_heuristic(makefunction=True)

