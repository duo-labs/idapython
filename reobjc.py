import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_search
import ida_struct
import ida_typeinf
import idautils
import ida_ua
import re
import sys
import traceback

class REobjc:
    '''
    Todd Manning
    tmanning@duo.com
    https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro
    
    Code to assist in reverse engineering MacOS Objective C binaries.
    Currently this code is Intel x64 specific, and doesn't handle ARM/iOS.
    
    New cross references are made to Objective C methods located in the binary. 
    
    '''
    
    
    def __init__(self, autorun=False):
        # 
        self.ea = None
        self.printflag = False
        self.verboseflag = False
        self.debugflag = False
        self.printxrefs = True
        self.target_objc_msgsend = []
        self._locate_objc_runtime_functions()
        if autorun:
            self.run()
        return None

    def _locate_objc_runtime_functions(self):
        '''
        Find the references to 
        id objc_msgSend(id self, SEL op, ...);
        This is the target of all calls and jmps for ObjC calls.
        
        RDI == self
        RSI == selector
        X86/64 args: RDI, RSI, RDX, RCX, R8, R9 ... 
        
        This function populates self.target_objc_msgsend with the intention of
        using this array in other functions to find indirect calls to the various
        ways objc_msgsend is referenced in binaries.
        
        The negative_reg variable below is blank, but is included in case some functions need to be excluded...
        
        TODO: Handle all other objective c runtime functions, not just objc_msgsend
        TODO: generalize to all architectures
        TODO: check that the matched names are in the proper mach-o sections based on the address in the tuple
        '''
        positive_reg = re.compile('.*_objc_msgsend', re.IGNORECASE)
        negative_reg = re.compile('^$', re.IGNORECASE)
        
        if self.printflag: print "Finding Objective C runtime functions..."

        for name_tuple in idautils.Names(): # returns a tuple (address, name)
            addr, name = name_tuple
            if positive_reg.match(name) and not negative_reg.match(name):
                if self.printflag: print "0x%08x\t%s" % (addr, name)
                self.target_objc_msgsend.append(name_tuple)
        
        return None
        
    def lookup_objc_runtime_function(self, fname):
        '''
        Find a matching function (address,name) tuple in self.target_objc_msgsend
        Sometimes this name can have a register prepended to it, as with 'cs:selRef_setObject_forKey_'
        '''
        
        register_reg = re.compile('.*:')
        if register_reg.match(fname):
            fname = re.sub(register_reg, '', fname)
        
        function_ea = idc.get_name_ea_simple(fname)
        
        # fname is found
        if function_ea != idc.BADADDR:
            if self.debugflag: print "Looking for function %s" % fname
            
            # iterate over objc runtime functions
            for name_tuple in self.target_objc_msgsend:
                addr, name = name_tuple
                if fname == name:
                    if self.debugflag:  print "Found match: 0x%08x\t%s" % (addr, name)
                    return name_tuple
                
        return None
        
        
    def objc_msgsend_xref(self, call_ea, objc_self, objc_selector, create_xref = True):
        '''
        This function will create a code xref to an objc method
        
        call_ea : location of call/jmp objc_msgsend (regardless of direct/indirect)
        objc_self: ea where RDI is set to static value (or that we find it's from a previous call or the RDI of the current function)
        objc_selector: ea where RSI is set to static value
        
        This ignores the RDI register, which is the `self` argument to objc_msgsend()
        id objc_msgSend(id self, SEL op, ...);
        So far, this seems to be fine as far as the cross-references are concerned.

        '''
        
        # get instruction mnemonic at address - I guess to check and make sure 
        # it's mov rsi, blah
        instruction = idc.GetDisasm(objc_selector)
        if self.debugflag: print ">>> objc_msgsend_xref 0x%08x %s" % (objc_selector, instruction)
        
        # get outbound references in the appropriate segment
        # implicit assumption is there is exacltly one
        target_selref = None
        for _ref in idautils.DataRefsFrom(objc_selector):
            if idc.SegName(_ref) == "__objc_selrefs":
                target_selref = _ref
                
        if not target_selref:
            return False
            
        # get outbound references in the appropriate segment
        # implicit assumption is there is exacltly one
        target_methname = None
        for _ref in idautils.DataRefsFrom(target_selref):
            if idc.SegName(_ref) == "__objc_methname":
                target_methname = _ref
                
        if not target_methname:
            return False
        
        # get inbound references
        # __objc_const
        # must be a __objc2_meth
        # I hope this method is correct to find __objc2_meth structs
        # BUG: when the binary has mutiple objc methods by the same name, this logic fails
        # Track RDI register. have to figure out what instance/class is referenced
        objc2_meth_struct_id = ida_struct.get_struc_id("__objc2_meth")
        meth_struct_found = False
        target_method = None
        for _ref in idautils.DataRefsTo(target_methname):
            # multiple may match
            # we care about the __obj2_meth struct found in references
            if idc.SegName(_ref) == "__objc_const":
                # check the outbound references
                for _meth_ref in idautils.DataRefsFrom(_ref):
                    if _meth_ref == objc2_meth_struct_id:
                        meth_struct_found = True
                
                if meth_struct_found:
                    # only do this once
                    # TODO: check against RDI here to make sure it's the proper class
                    # meth_struct_found = False 
                    
                    for _meth_ref in idautils.DataRefsFrom(_ref):
                        # assumption made on function always being in text segment
                        if idc.SegName(_meth_ref) == "__text":
                            # save the method implementation -- this is the function ptr
                            if self.debugflag: print "0x%08x checking for the proper method -- %s" % (_meth_ref, idc.get_name(idc.get_func_attr(_meth_ref, idc.FUNCATTR_START)))
                            target_method = _meth_ref

        if not target_method:
            return False
        
        # After dereferencing across the IDB file, we finally have a target function. 
        # In other words, if there isn't a method **in this binary** no xref is made (IDA only loads one binary?)
        # that is referenced from the mov rsi, <selector> instruction
        if self.debugflag: print "Found target method 0x%08x" % target_method
        if create_xref: idc.AddCodeXref(objc_selector, target_method, idc.fl_CF)
        
        return True


    def run(self):
        '''
        This method will iterate over each function
        '''
        for f in idautils.Functions():
            
            f_start = f # idc.get_func_attr(f, idc.FUNCATTR_START)
            f_end   = idc.get_func_attr(f, idc.FUNCATTR_END)
            
            try:
                self.find_objc_calls(f)
            except Exception as e:
                fname = idc.get_name(idc.get_func_attr(f, idc.FUNCATTR_START))
                print "\n\n[!!] Exception processing function %s: %s @ ea = 0x%08x (%dL)" % (fname, e, self.ea, self.ea)
                traceback.print_exc()
                print "\n\n"
                
            

    # f is an address in a function
    # done so there's not a requirement for f to be the start of a function. 
    # f = ScreenEA()
    def find_objc_calls(self, f):

            f_start = idc.get_func_attr(f, idc.FUNCATTR_START)
            f_end   = idc.get_func_attr(f, idc.FUNCATTR_END)
        
            for ea in idautils.Heads(f_start, f_end):
                if self.debugflag: print "0x%08x '%s'" % (ea, idc.GetMnem(ea))

                objc_selector = None
                objc_selector_ea = None
                
                # TODO ARM branching (B, BL, BX, BLX)
                # TODO ARM registers (R0..R7)
                if idc.GetMnem(ea) == "call" or idc.GetMnem(ea) == "jmp":
                    
                    # global tracking of ea (only in this loop) to cite when exceptions are caught
                    self.ea = ea
                    
                    call_ea = ea
                    call_operand = idc.GetOpnd(call_ea, 0)
                    call_type = None
                    call_target = None
                    
                    # is this a CALL <REG> or CALL <MEMORY_LOC>
                    # call_target is the address of the function being called
                    # for indirect calls, resolve the register into a value
                    # for direct calls, pull the value from the first operand
                    if idc.get_operand_type(call_ea,0) == ida_ua.o_reg:
                        call_type = "indirect"                        
                        target_register = call_operand
                        call_target_dict = self.resolve_register_backwalk_ea(call_ea, target_register)
                        if call_target_dict:
                            call_target = call_target_dict["value"]
                    else:
                        call_type = "direct"
                        call_target = call_operand
                    
                    # check the list of functions from the objc runtime
                    # call_target should be validated here, in case something fails with resolve_register_backwalk_ea()
                    if call_target and self.lookup_objc_runtime_function(call_target):
                        if self.debugflag: print "%s call, operand_type == %s" % (call_type, idc.get_operand_type(call_ea,0))
                        
                        # get the argument values at the call
                        # id objc_msgSend(id self, SEL op, ...);
                        # inefficient to get all these if they're not needed
                        # returns dict
                        # TODO Eliminate hardcoded x64
                        objc_self     = rdi = self.resolve_register_backwalk_ea(call_ea, "rdi")
                        objc_selector = rsi = self.resolve_register_backwalk_ea(call_ea, "rsi")
                        arg1_selector = rdx = self.resolve_register_backwalk_ea(call_ea, "rdx")
                        arg2_selector = rcx = self.resolve_register_backwalk_ea(call_ea, "rcx")
                        arg3_selector = r8  = self.resolve_register_backwalk_ea(call_ea, "r8")
                        arg4_selector = r9  = self.resolve_register_backwalk_ea(call_ea, "r9")
                        
                        # RDI is the self pointer
                        # if RDI used in objc_msgsend is the same value passed into this function, 
                        # resolve_register_backwalk_ea will return {value: rdi...}
                        # RDI is self, so figure out which class that self is
                        # This code presumes that resolve_register_backwalk_ea() will find *some value* for RDI...
                        # what if RDI is None? If the method is actually a selector, we can presume RDI is self, and pull 
                        # the class from the type of the first argument to the current function
                        # TODO add a check for ``not rdi`` here
                        if not objc_self:
                            # if RDI is None, that means the call is being sent to self
                            # the first objc call on self wouldn't need to set an RDI value (because it was already set)
                            
                            # get the class from the function parameter type
                            objc_class = self.resolve_objc_self_to_class(call_ea)
                            
                            # create a faked RDI dict
                            # _faked_ key set here to differentiate from a 'real' RDI dict
                            # TODO eliminate hardcoded x64
                            objc_self = rdi = {"_faked_" : True, "target" : "rdi", "value" : "rdi", "target_ea" : f_start, "ea" : call_ea, "type" : -1}
                        
                        # TODO eliminate hardcoded x64
                        if objc_self and objc_self['value'] == 'rdi':
                            objc_class = self.resolve_objc_self_to_class(objc_self['target_ea'])
                            if self.debugflag: print "### objc_class == %s" % objc_class
                        
                        # objc_selector: address of instruction mov rsi, <selector>
                        if objc_self and objc_selector:
                            xref_created = self.objc_msgsend_xref(call_ea, objc_self['target_ea'], objc_selector['target_ea'])
                            if self.printxrefs and xref_created: print "0x%08x Creating xref: %s %s, %s" % (ea, idc.GetMnem(ea), idc.GetOpnd(ea, 0), objc_selector['value'])



    def resolve_register_backwalk_ea(self, ea, target_dest_reg):
        '''
        Starting at ea, walk backward and locate the first instruction assigning a value to the target_register
        Keep walking backward, tracking the ultimate source to some value (register, variable, memory, etc)
        
        Assumption: ea is inside a function
        
        In some cases, target_dest_reg might resolve to a register used as a function argument (RDI, RSI, RDX, RCX, R8, R9)
        Callers will have to do something about that. Inferring the type and/or instance from the argument registers above
        
        Return: dict with keys ea, value
        
        Issues:
        1 RAX tracking should track through as many calls as necessary. Right now, if multiple calls are made on an object 
          (which is common in objc - alloc, init, <do something>), this code doesn't handle properly. 
          Essentially the class used in alloc results in rax of the instance, 
          and that RAX returned eventually is the RDI in the call to <do something>
          Since this code returns previous_call in the returned dict, you could recursively call resolve_register_backwalk_ea
          using the previous_call EA until RDI is not from a previous call
        2 register tracking breaks when referencing registers of different bitwidths e.g. RAX/EAX/AL
        3 when ea points to a CALL <target_dest_reg>, the value of <target_dest_reg> isn't found. Workaround by passing ea-1
        4 Doesn't handle backwalking basic blocks that have multiple incoming edges. 
            In reality, there are cases where the target may have any number of values.
            Handle this by maybe showing all the values... ugh yuk
            For the case of objc methods, I haven't seen this matter much yet, but backtracing e.g. locals is affected more often
        4 LEA. Add instructions for Arm architecture
        5 Proper checking against RDI -- this fixes the issues around multiple subclasses of a common parent sharing method names
        '''
        
        f_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        f_end   = idc.get_func_attr(ea, idc.FUNCATTR_END)

        curr_ea = ea
        dst = None
        src = None
        
        target = target_dest_reg
        target_value = None
        target_ea = idc.BADADDR
        target_type = None
        previous_call = None
        
        ret_dict = {}
 
        # adjustment for issue 3 above
        # TODO Eliminate hardcoded x64
        if idc.GetMnem(curr_ea) == "call" and idc.GetOpnd(curr_ea, 0) == target_dest_reg:
            curr_ea = idc.prev_head(curr_ea-1, f_start) 
        

        while curr_ea != idc.BADADDR:
            instruction = idc.GetDisasm(curr_ea)
                        
            if self.debugflag: print "0x%08x %s" % (curr_ea, instruction)
            
            # looking for the previous place this register was assigned a value
            mnem = idc.GetMnem(curr_ea)
            dst  = idc.GetOpnd(curr_ea, 0)
            src  = idc.GetOpnd(curr_ea, 1)
            
            # X64 specific
            # TODO: generalize to other architectures
            if dst == target and (mnem == "mov" or mnem == "lea"):
                target = src
                target_value = src
                target_ea = curr_ea
                target_type = idc.get_operand_type(curr_ea,1)
                if self.debugflag: print "            new target set %s (type=%d)" % (target, idc.get_operand_type(curr_ea,1))
                        
            # take stab at tracking calls - this is not the greatest approach, but slightly more correct than doing no tracking
            # call instruction affects RAX if it returns a result
            # 
            if dst == target == "rax" and mnem == "call":
                target_value = "<return from previous call>"
                previous_call = curr_ea
                break


            # step to previous instruction 
            curr_ea = idc.prev_head(curr_ea-1, f_start)

        if target_value: 
            if self.verboseflag: print ">>> 0x%08x, %s is set to %s @ 0x%08x" % (ea, target_dest_reg, target_value, target_ea)
            ret_dict = {"target" : target_dest_reg, "value" : target_value, "target_ea" : target_ea, "ea" : ea, "type" : target_type}

            if previous_call:
                ret_dict["previous_call"] = previous_call

            return ret_dict

        # fall through if nothing is found
        return None


    def resolve_objc_self_to_class(self, ea):
        '''
        Get the objective c class for the current function RDI value
        based on the class of the first argument to the current function
        '''
        f_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        
        tif = ida_typeinf.tinfo_t()
        idaapi.get_tinfo2(f_start, tif)
        funcdata = idaapi.func_type_data_t()
        tif.get_func_details(funcdata)

        # not happy about casting to a string and then regex replacing... but that's the best I could come up with
        replace_reg = re.compile(' \*', re.IGNORECASE)
        objc_self_type = funcdata[0].type
        return objc_self_type
        
