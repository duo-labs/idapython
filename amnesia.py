import idc
import ida_bytes
import ida_funcs
import ida_search
import idautils

import re

class Amnesia:
    '''
    Filename:       amnesia.py
    Description:    IDA Python module for finding code in ARM binaries. 
    Contributors:   tmanning@duo.com, luis@ringzero.net, jmitch
    
    Notes:
    ------
    This code currently focuses more on Thumb detection. 
    Lots more work to do here on ARM and Thumb detection. 
    For ARM Cortex, this code works pretty well. It also 
    gave some good results with ARM Mach-o binaries. 
    
    This code will undergo continued development. Development might break scripts.
    '''
    
    printflag = False
    
    def find_function_epilogue_bxlr(self, makecode=False):
        '''
        Find opcode bytes corresponding to BX LR.
        This is a common way to return from a function call.
        Using the IDA API, convert these opcodes to code. This kicks off IDA analysis.
        '''
        EAstart = idc.MinEA()
        EAend   = idc.MaxEA()
    
        ea = EAstart
        length = 2 # this code isn't tolerant to values other than 2 right now

        fmt_string = "Possible BX LR 0x%08x == "
        for i in range(length):
            fmt_string += "%02x "
    
        while ea < EAend:
            instructions = []
            for i in range(length):
                instructions.append(idc.Byte(ea + i))

            if not ida_bytes.isCode(ida_bytes.getFlags(ea)) and instructions[0] == 0x70 and instructions[1] == 0x47:
                if self.printflag:
                    print(fmt_string % (ea, instructions[0], instructions[1]))
                if makecode:
                    idc.MakeCode(ea)
            ea = ea + length

    def find_pushpop_registers_thumb(self, makecode=False):
        '''
        Look for opcodes that push registers onto the stack, which are indicators of function prologues.
        Using the IDA API, convert these opcodes to code. This kicks off IDA analysis.
        '''
        
        '''
        thumb register list from luis@ringzero.net
        '''
        
        thumb_reg_list = [0x00, 0x02, 0x08, 0x0b, 0x0e, 0x10, 0x1c, 0x1f, 0x30, 0x30, 0x38, 0x3e, 0x4e, 
        0x55, 0x70, 0x72, 0x73, 0x7c, 0x7f, 0x80, 0x90, 0xb0, 0xf0, 0xf3, 0xf7, 0xf8, 0xfe, 0xff]
        
        EAstart = idc.MinEA()
        EAend   = idc.MaxEA()
    
        ea = EAstart
        length = 2 # this code isn't tolerant to values other than 2 right now

        fmt_string = "Possible Function 0x%08x == "
        for i in range(length):
            fmt_string += "%02x "
    
        while ea < EAend:
            instructions = []
            for i in range(length):
                instructions.append(idc.Byte(ea + i))

            if not ida_bytes.isCode(ida_bytes.getFlags(ea)) and instructions[0] in thumb_reg_list and (instructions[1] == 0xb5 or instructions[1]== 0xbd):
                if self.printflag:
                    print(fmt_string % (ea, instructions[0], instructions[1]))
                if makecode:
                    idc.MakeCode(ea)
            ea = ea + length

    def find_pushpop_registers_arm(self, makecode=False):
        '''
        Find opcodes for PUSH/POP registers in ARM mode
        Using the IDA API, convert these opcodes to code. This kicks off IDA analysis.
        
        bigup jmitch
        ** ** 2d e9 and ** ** bd e8
        '''
        
        EAstart = idc.MinEA()
        EAend   = idc.MaxEA()
    
        ea = EAstart
        length = 2 # this code isn't tolerant to values other than 2 right now

        fmt_string = "Possible %s {REGS} 0x%08x == "
        for i in range(length):
            fmt_string += "%02x "
    
        while ea < EAend:
            instructions = []
            for i in range(length):
                instructions.append(idc.Byte(ea + i))

            # print BX LR bytes
            if not ida_bytes.isCode(ida_bytes.getFlags(ea)) and      \
            (instructions[0] == 0xbd and instructions[1] == 0xe8): 
                if self.printflag:
                    print(fmt_string % ("POP ", ea, instructions[0], instructions[1]))
                if makecode:
                    idc.MakeCode(ea)
            
            if not ida_bytes.isCode(ida_bytes.getFlags(ea)) and      \
            (instructions[0] == 0x2d and instructions[1] == 0xe9)    \
            :
                if self.printflag:
                    print(fmt_string % ("PUSH", ea, instructions[0], instructions[1]))
                if makecode: 
                    idc.MakeCode(ea)
            ea = ea + length

    def make_new_functions_heuristic_push_regs(self, makefunction=False):
        '''
        After converting bytes to instructions, Look for PUSH instructions that are likely the beginning of functions.
        Convert these code areas to functions.
        '''
        EAstart = idc.MinEA()
        EAend   = idc.MaxEA()
        ea = EAstart
        
        while ea < EAend:
            if self.printflag:
                print("EA %08x" % ea)
            
            ea_function_start = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
            
            # If ea is inside a defined function, skip to end of function
            if ea_function_start != idc.BADADDR:
                ea = idc.FindFuncEnd(ea)
                continue

            # If current ea is code
            if ida_bytes.isCode(ida_bytes.getFlags(ea)):
                # Looking for prologues that do PUSH {register/s}
                mnem = idc.GetMnem(ea)
                
                # 
                if (
                    mnem == "PUSH"
                ):
                    if makefunction:
                        if self.printflag:
                            print("Converting code to function @ %08x" % ea)
                        idc.MakeFunction(ea)

                    eanewfunction = idc.FindFuncEnd(ea)
                    if eanewfunction != idc.BADADDR:
                        ea = eanewfunction
                        continue

            nextcode = ida_search.find_code(ea, idc.SEARCH_DOWN)
            
            if nextcode != idc.BADADDR:
                ea = nextcode
            else:
                ea += 1

    def nonfunction_first_instruction_heuristic(self, makefunction=False):
        EAstart = idc.MinEA()
        EAend   = idc.MaxEA()
        ea = EAstart
        
        flag_code_outside_function = False
        self.printflag = False
        
        while ea < EAend:

            # skip functions, next instruction will be the target to inspect
            function_name = idc.GetFunctionName(ea)
            if function_name != "":

                flag_code_outside_function = False

                # skip to end of function and keep going
                # ea = idc.FindFuncEnd(ea)
                #if self.printflag:
                #    print "Skipping function %s" % (function_name)

                ea = ida_search.find_not_func(ea, 1)
                continue

            elif ida_bytes.isCode(ida_bytes.getFlags(ea)):

                # code that is not a function
                # get mnemonic to see if this is a push
                mnem = idc.GetMnem(ea)
                
                if makefunction and (mnem == "PUSH" or mnem == "PUSH.W" or mnem == "STM" or mnem=="MOV"):
                    if self.printflag:
                        print("nonfunction_first_instruction_heuristic() making function %08x" % ea)
                    idc.MakeFunction(ea)
                    flag_code_outside_function = False
                    ea =ida_search.find_not_func(ea, 1)
                    continue
                
                else:
                    if self.printflag:
                        print("nonfunction_first_instruction_heuristic() other instruction %08x\t'%s'" % (ea, mnem))
                    ea = idc.NextFunction(ea)
                    continue

            ea += 1

