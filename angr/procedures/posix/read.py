import angr
from angr.sim_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# read
######################################

class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)
        
        try:
            simfd = self.state.posix.get_fd(fd)
            if simfd is None:
                return -1

            return simfd.read(dst, length)
        except angr.SimUnsatError:
            return self.state.se.Unconstrained('read', 32, uninitialized=False)
