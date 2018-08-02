import angr

import logging
l = logging.getLogger("angr.procedures.syscalls.lseek")

class lseek(angr.SimProcedure):

    IS_SYSCALL = True

    def run(self, fd, seek, whence): #pylint:disable=arguments-differ,unused-argument

        if self.state.solver.symbolic(whence):
            err = "Symbolic whence is not supported in lseek syscall."
            l.error(err)
            raise angr.errors.SimPosixError(err)

        whence = self.state.solver.eval(whence)
        if whence == 0:
            whence_str = 'start'
        elif whence == 1:
            whence_str = 'current'
        elif whence == 2:
            whence_str = 'end'
        else:
            return -1

        # let's see what happens...
        #if self.state.se.symbolic(seek):
        #    err = "Symbolic seek is not supported in lseek syscall."
        #    l.error(err)
        #    raise angr.errors.SimPosixError(err)

        #seek = self.state.se.eval(seek)
        try:
            simfd = self.state.posix.get_fd(fd)
        except angr.SimUnsatError:
            # XXX: hase resymbolic
            return self.state.se.Unconstrained('lseek', self.state.arch.bits, uninitialized=False)
        if simfd is None:
            return -1
        success = simfd.seek(seek, whence_str)
        if self.state.solver.is_false(success):
            return -1
        return self.state.solver.If(success, simfd.tell(), -1)
