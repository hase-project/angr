import logging
import angr
from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger("angr.procedures.libc.snprintf")

######################################
# snprintf
######################################

class snprintf(FormatParser):

    ARGS_MISMATCH = True

    def run(self, dst_ptr, size):  # pylint:disable=arguments-differ,unused-argument
        try:
            # The format str is at index 2
            fmt_str = self._parse(2)
            out_str = fmt_str.replace(3, self.arg)
            self.state.memory.store(dst_ptr, out_str)

            # place the terminating null byte
            self.state.memory.store(dst_ptr + (out_str.size() / 8), self.state.se.BVV(0, 8))

            # size_t has size arch.bits
            return self.state.se.BVV(out_str.size()/8, self.state.arch.bits)
        except angr.SimUnsatError:
            return self.state.se.Unconstrained('sprintf', self.state.arch.bits, uninitialized=False)

