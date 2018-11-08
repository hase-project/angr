import claripy
import angr
from angr.sim_type import SimTypeString, SimTypeLength
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS

import logging
l = logging.getLogger(name=__name__)

class strlen_old(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s, wchar=False):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)

        if wchar:
            null_seq = self.state.solver.BVV(0, 16)
            step = 2
        else:
            null_seq = self.state.solver.BVV(0, 8)
            step = 1

        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len

        chunk_size = None
        if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
            chunk_size = 1

        if self.state.mode == 'static':

            self.max_null_index = 0

            # Make sure to convert s to ValueSet
            s_list = self.state.memory.normalize_address(s, convert_to_valueset=True)

            length = self.state.solver.ESI(self.state.arch.bits)
            for s_ptr in s_list:

                r, c, i = self.state.memory.find(s, null_seq, max_str_len, max_symbolic_bytes=max_symbolic_bytes, step=step, chunk_size=chunk_size)

                self.max_null_index = max([self.max_null_index] + i)

                # Convert r to the same region as s
                r_list = self.state.memory.normalize_address(r, convert_to_valueset=True, target_region=next(iter(s_ptr._model_vsa.regions.keys())))

                for r_ptr in r_list:
                    length = length.union(r_ptr - s_ptr)

            return length

        else:
            search_len = max_str_len
            r, c, i = self.state.memory.find(s, null_seq, search_len, max_symbolic_bytes=max_symbolic_bytes, step=step, chunk_size=chunk_size)

            # try doubling the search len and searching again
            s_new = s
            while all(con.is_false() for con in c):
                s_new += search_len
                search_len *= 2
                r, c, i = self.state.memory.find(s_new, null_seq, search_len, max_symbolic_bytes=max_symbolic_bytes, step=step, chunk_size=chunk_size)
                # stop searching after some reasonable limit
                if search_len > 0x10000:
                    raise angr.SimMemoryLimitError("strlen hit limit of 0x10000")

            self.max_null_index = max(i)
            self.state.add_constraints(*c)
            result = r - s
            if result.depth > 3:
                rresult = claripy.BVS('strlen', len(result))
                self.state.solver.add(result == rresult)
                result = rresult
            return result


class strlen(strlen_old):
    def run(self, s, wchar=False):
        try:
            return super().run(s, wchar)
        except angr.SimUnsatError:
            self.max_null_index = self.state.libc.max_str_len
            return self.state.solver.Unconstrained('strlen', 64, uninitialized=False)
