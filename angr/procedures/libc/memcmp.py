import angr
from angr.sim_type import SimTypeTop, SimTypeLength, SimTypeInt

import logging
l = logging.getLogger(name=__name__)

class memcmp_old(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s1_addr, s2_addr, n):
        # TODO: look into smarter types here
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeInt(32, True)

        max_memcmp_size = self.state.libc.max_buffer_size

        definite_size = self.state.solver.min_int(n)
        conditional_s1_start = s1_addr + definite_size
        conditional_s2_start = s2_addr + definite_size
        if self.state.solver.symbolic(n):
            conditional_size = int(max(max_memcmp_size - definite_size, 0))
        else:
            conditional_size = 0

        l.debug("Definite size %s and conditional size: %s", definite_size, conditional_size)

        if definite_size > 0:
            s1_part = self.state.memory.load(s1_addr, definite_size, endness='Iend_BE')
            s2_part = self.state.memory.load(s2_addr, definite_size, endness='Iend_BE')
            cases = [ [s1_part == s2_part, self.state.solver.BVV(0, self.state.arch.bits)], [self.state.solver.ULT(s1_part, s2_part), self.state.solver.BVV(-1, self.state.arch.bits)], [self.state.solver.UGT(s1_part, s2_part), self.state.solver.BVV(1, self.state.arch.bits) ] ]
            definite_answer = self.state.solver.ite_cases(cases, 2)
            constraint = self.state.solver.Or(*[c for c,_ in cases])
            self.state.add_constraints(constraint)

            l.debug("Created definite answer: %s", definite_answer)
            l.debug("Created constraint: %s", constraint)
            l.debug("... crom cases: %s", cases)
        else:
            definite_answer = self.state.solver.BVV(0, self.state.arch.bits)

        if not self.state.solver.symbolic(definite_answer) and self.state.solver.eval(definite_answer) != 0:
            return definite_answer

        if conditional_size > 0:
            s1_all = self.state.memory.load(conditional_s1_start, conditional_size, endness='Iend_BE')
            s2_all = self.state.memory.load(conditional_s2_start, conditional_size, endness='Iend_BE')
            conditional_rets = { 0: definite_answer }

            for byte, bit in zip(range(conditional_size), range(conditional_size*8, 0, -8)):
                s1_part = s1_all[conditional_size*8-1 : bit-8]
                s2_part = s2_all[conditional_size*8-1 : bit-8]
                cases = [ [s1_part == s2_part, self.state.solver.BVV(0, self.state.arch.bits)], [self.state.solver.ULT(s1_part, s2_part), self.state.solver.BVV(-1, self.state.arch.bits)], [self.state.solver.UGT(s1_part, s2_part), self.state.solver.BVV(1, self.state.arch.bits) ] ]
                conditional_rets[byte+1] = self.state.solver.ite_cases(cases, 0)
                self.state.add_constraints(self.state.solver.Or(*[c for c,_ in cases]))

            ret_expr = self.state.solver.If(definite_answer == 0, self.state.solver.ite_dict(n - definite_size, conditional_rets, 2), definite_answer)
            self.state.add_constraints(self.state.solver.Or(*[n-definite_size == c for c in conditional_rets.keys()]))
            return ret_expr
        else:
            return definite_answer

class memcmp(memcmp_old):
    def run(self, s1_addr, s2_addr, n):
        try:
            return super().run(s1_addr, s2_addr, n)
        except angr.SimUnsatError:
            return self.state.solver.Unconstrained('memcmp', 32, uninitialized=False)
