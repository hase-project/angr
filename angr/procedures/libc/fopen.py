import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

######################################
# fopen
######################################

# NOTE: non-standard c/e flag for fopen
# http://man7.org/linux/man-pages/man3/fopen.3.html#NOTES
def mode_to_flag(mode):
    if mode[-1] == ord('b'): # lol who uses windows
        mode = mode[:-1]
    mode = mode.replace(b'c', b'').replace(b'e', b'')
    all_modes = {
        b"r"  : angr.storage.file.Flags.O_RDONLY,
        b"r+" : angr.storage.file.Flags.O_RDWR,
        b"w"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT,
        b"w+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT,
        b"a"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND,
        b"a+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND
        }
    if mode not in all_modes:
        raise angr.SimProcedureError('unsupported file open mode %s' % mode)

    return all_modes[mode]

class fopen(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, p_addr, m_addr):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        try:
            p_strlen = self.inline_call(strlen, p_addr)
            m_strlen = self.inline_call(strlen, m_addr)
            p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
            m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness='Iend_BE')
            try:
                path = self.state.solver.eval(p_expr, cast_to=bytes)
            except angr.SimUnsatError:
                # XXX: fopen on unsat path does wrong on max_null_index
                p_expr = self.state.memory.load(p_addr, endness='Iend_BE')
                path = self.state.solver.eval(p_expr, cast_to=bytes)
            mode = self.state.solver.eval(m_expr, cast_to=bytes)

            # TODO: handle append
            fd = self.state.posix.open(path, mode_to_flag(mode))

            if fd is None:
                # if open failed return NULL
                return 0
            else:
                # Allocate a FILE struct in heap
                malloc = angr.SIM_PROCEDURES['libc']['malloc']
                io_file_data = io_file_data_for_arch(self.state.arch)
                file_struct_ptr = self.inline_call(malloc, io_file_data['size']).ret_expr

                # Write the fd
                fd_bvv = self.state.solver.BVV(fd, 4 * 8) # int
                self.state.memory.store(file_struct_ptr + io_file_data['fd'],
                                        fd_bvv,
                                        endness=self.state.arch.memory_endness)

                return file_struct_ptr
        except angr.SimUnsatError:
            return 0
