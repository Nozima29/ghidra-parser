from ghidra.app.util.bin.format.elf import *
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util.opinion import ElfLoader
import ghidra.app.util.bin.format.elf.ElfDefaultGotPltMarkup
import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.program.model.address.AddressSet
from ghidra.util.task import ConsoleTaskMonitor

import os

class GhidraAPI:
    def __init__(self):
        self.func_corpus = dict()
        self._init_state()
        self.linker_funcs = ['__libc_csu_init', '__libc_csu_fini', 'deno_normister_tm_clones', '_start',
                 'no_normister_tm_clones', '__do_global_dtors_aux', 'frame_dummy']
    

    def _init_state(self):
        state = getState()
        program = state.getCurrentProgram()        
        self.bin_name = program.getName()        
        self.sections = program.getMemory().getBlocks()
        self.code_block = program.getMemory().getBlock(".text")
        self.listing = program.getListing()    
        self.af = program.getAddressFactory()
        self.functions = program.getFunctionManager().getFunctions(True)
        

    def get_section_names(self):
        names = list()
        for section in self.sections:            
            names.append(section.getName())
        return names


    def clean(self, instr):        
        instr = instr.replace(' + ', '+').replace(' - ', '-') \
                     .replace(' ', '_').replace(',_', ', ') \
                     .replace('!', '').replace(',', '_') \
                     .replace('#', '').replace(' #', '') \
                     .replace(' ', '').replace('_-', '-') \
                     .replace('_+', '+').lower() 
        return instr


    def get_exec_functions(self): 
        funcs = self.functions
        textset = self.af.getAddressSet(self.code_block.getStart(), self.code_block.getEnd())     
        text_funcs = filter(lambda f: textset.contains(f.getEntryPoint()), funcs)
        return text_funcs
    

    def store_code_units(self): 
        exec_funcs = self.get_exec_functions()               
        for func in exec_funcs:
            f_name = func.getName()                        
            if 'FUN_' in f_name or f_name in self.linker_funcs: continue               
            addrset = func.getBody()
            codeUnits = self.listing.getCodeUnits(addrset, True)
            instrs = list()                
            
            for codeUnit in codeUnits:                                
                i = codeUnit.toString()
                i = self.clean(i)       
                if i == 'nop': continue 
                instrs.append(i)                
            
            code = ', '.join(instrs)
            
            # remove functions containing only ret instruction            
            if len(code) > 5:            
                self.func_corpus[code] = f_name        
    
    def validate_path(self, dir):
        if not os.path.exists(dir):
            os.makedirs(dir)

    def save_bin_info(self, out_dir): 
        self.validate_path(out_dir)
        self.store_code_units()        
        out_file = '{}/{}.txt'.format(out_dir, self.bin_name)        
        with open(out_file, 'w') as f:
            for code, fname in self.func_corpus.items():
                f.write(fname + '\t' + code + '\n')
            
        
if __name__ == '__main__':        
    api = GhidraAPI()
    api.save_bin_info(out_dir='./src/outputs')
    
    
    
    
    