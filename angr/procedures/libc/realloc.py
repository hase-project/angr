import angr
from angr.sim_type import SimTypeLength, SimTypeTop
from .malloc import malloc

import logging
l = logging.getLogger("angr.procedures.libc.realloc")

######################################
# realloc
######################################

# FIXME: If ptr is a null pointer, realloc() shall be equivalent to malloc() for the specified size.
class realloc(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr, size):

        
        if not self.state.se.symbolic(ptr) and \
            self.state.se.eval(ptr) == 0:            
            return self.inline_call(malloc, size).ret_expr

        try:
            self.state.add_constraints(size <= self.state.libc.max_variable_size)
            size_int = self.state.se.max_int(size)

            l.debug("Size: %d", size_int)
            self.state.add_constraints(size_int == size)
        except:
            size_int = self.state.libc.max_variable_size

        self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
                                1: SimTypeLength(self.state.arch) }
        self.return_type = self.ty_ptr(SimTypeTop(size))

        addr = self.state.libc.heap_location

        if self.state.solver.eval(ptr) != 0:
            v = self.state.memory.load(ptr, size_int)
            self.state.memory.store(addr, v)
            
        self.state.libc.heap_location += size_int

        return addr
