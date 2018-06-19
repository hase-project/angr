import angr

from . import io_file_data_for_arch

######################################
# fread
######################################

class fread(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        try:
            ret = simfd.read(dst, size * nm)
            return self.state.se.If(self.state.se.Or(size == 0, nm == 0), 0, ret / size)
        except:
            length = size * nm
            if self.state.se.symbolic(length):
                try:
                    length = max(self.state.se.min(length), min(self.state.se.max(length), 0x1000))
                except:
                    length = self.state.libc.max_variable_size
            else:
                length = self.state.se.eval(length)
            self.state.memory.store(dst, self.state.se.BVS('fread', length * 8))
            return self.state.se.BVS('fread', 32)
