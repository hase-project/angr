import angr
from angr.sim_type import SimTypeFd, SimTypeTop

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import logging
l = logging.getLogger(name=__name__)


######################################
# fileno
######################################


class fileno(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, f):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        self.return_type = SimTypeFd()

        # Get FILE struct
        io_file_data = io_file_data_for_arch(self.state.arch)

        # Get the file descriptor from FILE struct
        try:
            result = self.state.mem[f + io_file_data['fd']].int.resolved
            return result.sign_extend(self.arch.bits - len(result))
        except angr.SimUnsatError:
            # XXX: hase -> resymbolic
            return self.state.solver.Unconstrained("fileno_fd", 32, uninitialized=False)
