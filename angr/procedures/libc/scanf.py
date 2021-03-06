import logging
import angr
from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_type import SimTypeInt, SimTypeString

l = logging.getLogger(name=__name__)

class scanf(FormatParser):
    #pylint:disable=arguments-differ, unused-argument

    def run(self, fmt):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)
        try:
            fmt_str = self._parse(0)

            # we're reading from stdin so the region is the file's content
            simfd = self.state.posix.get_fd(0)
            if simfd is None:
                return -1

            items = fmt_str.interpret(1, self.arg, simfd=simfd)
            return items
        except angr.SimUnsatError:
            return self.state.solver.Unconstrained('scanf', 32, uninitialized=False)
