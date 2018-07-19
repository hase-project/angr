from string import digits as ascii_digits
import logging
import math
import claripy
import signal

from ... import sim_type
from ...sim_procedure import SimProcedure
from ...storage.file import SimPackets

l = logging.getLogger("angr.procedures.stubs.format_parser")


def timeout(seconds=10):
    def decorator(func):
        original_handler = signal.getsignal(signal.SIGALRM)
        def _handle_timeout(signum, frame):
            signal.signal(signal.SIGALRM, original_handler)
            raise Exception("Timeout")
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            except:
                Exception("Timeout")
            finally:
                signal.alarm(0)
            return result
        return wrapper

    return decorator


class FormatString(object):
    """
    Describes a format string.
    """

    SCANF_DELIMITERS = ["\x09", "\x0a", "\x0b", "\x0d", "\x20"]

    def __init__(self, parser, components):
        """
        Takes a list of components which are either just strings or a FormatSpecifier.
        """
        self.components = components
        self.parser = parser
        self.string = None

    @property
    def state(self):
        return self.parser.state

    @staticmethod
    def _add_to_string(string, c):
        if c is None:
            return string
        if string is None:
            return c
        return string.concat(c)

    def _get_str_at(self, str_addr):

        strlen = self.parser._sim_strlen(str_addr)

        #TODO: we probably could do something more fine-grained here.

        # throw away strings which are just the NULL terminator
        if self.parser.state.se.max_int(strlen) == 0:
            return None
        return self.parser.state.memory.load(str_addr, strlen)

    def replace(self, startpos, args):
        """
        Implement printf - based on the stored format specifier information, format the values from the arg getter function `args` into a string.

        :param startpos:        The index of the first argument to be used by the first element of the format string
        :param args:            A function which, given an argument index, returns the integer argument to the current function at that index
        :return:                The result formatted string
        """

        argpos = startpos
        string = None

        for component in self.components:
            # if this is just concrete data
            if isinstance(component, str):
                string = self._add_to_string(string, self.parser.state.se.BVV(component))
            elif isinstance(component, claripy.ast.BV):
                string = self._add_to_string(string, component)
            else:
                # okay now for the interesting stuff
                # what type of format specifier is it?
                fmt_spec = component
                if fmt_spec.spec_type == 's':
                    str_ptr = args(argpos)
                    string = self._add_to_string(string, self._get_str_at(str_ptr))
                # integers, for most of these we'll end up concretizing values..
                else:
                    i_val = args(argpos)
                    if fmt_spec.spec_type == 'n':
                        self.state.memory.store(i_val, self.state.se.BVS('format_%n', self.state.arch.bits))
                    else:
                        c_val = int(self.parser.state.se.eval(i_val))
                        c_val &= (1 << (fmt_spec.size * 8)) - 1
                        if fmt_spec.signed and (c_val & (1 << ((fmt_spec.size * 8) - 1))):
                            c_val -= (1 << fmt_spec.size * 8)

                        if fmt_spec.spec_type in ('d', 'i'):
                            s_val = str(c_val)
                        elif fmt_spec.spec_type == 'u':
                            s_val = str(c_val)
                        elif fmt_spec.spec_type == 'c':
                            s_val = chr(c_val & 0xff)
                        elif fmt_spec.spec_type == 'x':
                            s_val = hex(c_val)[2:].rstrip('L')
                        elif fmt_spec.spec_type == 'o':
                            s_val = oct(c_val)[1:].rstrip('L')
                        elif fmt_spec.spec_type == 'p':
                            s_val = hex(c_val).rstrip('L')
                        else:
                            raise SimProcedureError("Unimplemented format specifier '%s'" % fmt_spec.spec_type)

                        string = self._add_to_string(string, self.parser.state.se.BVV(s_val))

                argpos += 1

        return string

    def interpret(self, startpos, args, addr=None, simfd=None):
        """
        implement scanf - extract formatted data from memory or a file according to the stored format
        specifiers and store them into the pointers extracted from `args`.

        :param startpos:    The index of the first argument corresponding to the first format element
        :param args:        A function which, given the index of an argument to the function, returns that argument
        :param addr:        The address in the memory to extract data from, or...
        :param simfd:       A file descriptor to use for reading data from
        :return:            The number of arguments parsed
        """
        if simfd is not None and isinstance(simfd.read_storage, SimPackets):
            argnum = startpos
            for component in self.components:
                if type(component) is bytes:
                    sdata, _ = simfd.read_data(len(component), short_reads=False)
                    self.state.solver.add(sdata == component)
                elif isinstance(component, claripy.Bits):
                    sdata, _ = simfd.read_data(len(component) // 8, short_reads=False)
                    self.state.solver.add(sdata == component)
                elif component.spec_type == 's':
                    if component.length_spec is None:
                        sdata, slen = simfd.read_data(self.state.libc.buf_symbolic_bytes)
                    else:
                        sdata, slen = simfd.read_data(component.length_spec)
                    for byte in sdata.chop(8):
                        self.state.solver.add(claripy.And(*[byte != char for char in self.SCANF_DELIMITERS]))
                    self.state.memory.store(args(argnum), sdata, size=slen)
                    self.state.memory.store(args(argnum) + slen, claripy.BVV(0, 8))
                    argnum += 1
                elif component.spec_type == 'c':
                    sdata, _ = simfd.read_data(1, short_reads=False)
                    self.state.memory.store(args(argnum), sdata)
                    argnum += 1
                elif component.spec_type in ['d', 'x', 'o']:
                    bits = component.size * 8
                    if component.spec_type == 'x':
                        base = 16
                    elif component.spec_type == 'o':
                        base = 8
                    else:
                        base = 10

                    # here's the variable representing the result of the parsing
                    target_variable = self.state.solver.BVS('scanf_' + component.string, bits,
                            key=('api', 'scanf', argnum - startpos, component.string))
                    negative = claripy.SLT(target_variable, 0)

                    # how many digits does it take to represent this variable fully?
                    max_digits = int(math.ceil(math.log(2**bits, base)))

                    # how many digits does the format specify?
                    spec_digits = component.length_spec

                    # how many bits can we specify as input?
                    available_bits = float('inf') if spec_digits is None else spec_digits * math.log(base, 2)
                    not_enough_bits = available_bits < bits

                    # how many digits will we model this input as?
                    digits = max_digits if spec_digits is None else spec_digits

                    # constrain target variable range explicitly if it can't take on all possible values
                    if not_enough_bits:
                        self.state.solver.add(self.state.solver.And(
                            self.state.solver.SLE(target_variable, (base**digits) - 1),
                            self.state.solver.SGE(target_variable, -(base**(digits - 1) - 1))))

                    # perform the parsing in reverse - constrain the input digits to be the string version of the input
                    # this only works because we're reading from a packet stream and therefore nobody has the ability
                    # to add other constraints to this data!
                    # this makes z3's job EXTREMELY easy
                    sdata, _ = simfd.read_data(digits, short_reads=False)
                    for i, digit in enumerate(reversed(sdata.chop(8))):
                        digit_value = (target_variable / (base**i)) % base
                        digit_ascii = digit_value + ord('0')
                        if base > 10:
                            digit_ascii = claripy.If(digit_value >= 10, digit_value + (-10 + ord('a')), digit_ascii)

                        # if there aren't enough bits, we can increase the range by accounting for the possibility that
                        # the first digit is a minus sign
                        if not_enough_bits:
                            if i == digits - 1:
                                neg_digit_ascii = ord('-')
                            else:
                                neg_digit_value = (-target_variable / (base**i)) % base
                                neg_digit_ascii = neg_digit_value + ord('0')
                                if base > 10:
                                    neg_digit_ascii = claripy.If(neg_digit_value >= 10, neg_digit_value + (-10 + ord('a')), neg_digit_ascii)

                            digit_ascii = claripy.If(negative, neg_digit_ascii, digit_ascii)

                        self.state.solver.add(digit == digit_ascii[7:0])

                    self.state.memory.store(args(argnum), target_variable, endness=self.state.arch.memory_endness)
                    argnum += 1
                elif component.spec_type == 'n':
                    self.state.memory.store(args(argnum), self.state.se.BVS('format_%n', self.state.arch.bits))

            return argnum - startpos

        # TODO: we only support one format specifier in interpretation for now

        format_specifier_count = len(filter(lambda x: isinstance(x, FormatSpecifier), self.components))
        if format_specifier_count > 1:
            l.warning("We don't support more than one format specifiers in format strings.")

        if simfd is not None:
            region = simfd.read_storage
            addr = simfd._pos if hasattr(simfd, '_pos') else simfd._read_pos # XXX THIS IS BAD
        else:
            region = self.parser.state.memory

        bits = self.parser.state.arch.bits
        failed = self.parser.state.se.BVV(0, bits)
        argpos = startpos
        position = addr
        unreliable = False
        for component in self.components:
            if isinstance(component, str):
                # TODO we skip non-format-specifiers in format string interpretation for now
                # if the region doesn't match the concrete component, we need to return immediately
                pass
            else:
                fmt_spec = component
                try:
                    dest = args(argpos)
                except SimProcedureArgumentError:
                    dest = None
                if fmt_spec.spec_type == 's':
                    # set some limits for the find
                    max_str_len = self.parser.state.libc.max_str_len
                    max_sym_bytes = self.parser.state.libc.buf_symbolic_bytes

                    # has the length of the format been limited by the string itself?
                    if fmt_spec.length_spec is not None:
                        max_str_len = fmt_spec.length_spec
                        max_sym_bytes = fmt_spec.length_spec

                    # TODO: look for limits on other characters which scanf is sensitive to, '\x00', '\x20'
                    ohr, ohc, ohi = region.find(position, self.parser.state.se.BVV('\n'), max_str_len, max_symbolic_bytes=max_sym_bytes)

                    # if no newline is found, mm is position + max_strlen
                    # If-branch will really only happen for format specifiers with a length
                    mm = self.parser.state.se.If(ohr == 0, position + max_str_len, ohr)
                    # we're just going to concretize the length, load will do this anyways
                    length = self.parser.state.se.max_int(mm - position)
                    src_str = region.load(position, length)

                    # TODO all of these should be delimiters we search for above
                    # add that the contents of the string cannot be any scanf %s string delimiters
                    for delimiter in set(FormatString.SCANF_DELIMITERS):
                        delim_bvv = self.parser.state.se.BVV(delimiter)
                        for i in range(length):
                            self.parser.state.add_constraints(region.load(position + i, 1) != delim_bvv)

                    # write it out to the pointer
                    self.parser.state.memory.store(dest, src_str)
                    # store the terminating null byte
                    self.parser.state.memory.store(dest + length, self.parser.state.se.BVV(0, 8))

                    position += length

                else:

                    # XXX: atoi only supports strings of one byte
                    if fmt_spec.spec_type in ['d', 'i', 'u', 'x']:
                        base = 16 if fmt_spec.spec_type == 'x' else 10
                        try:
                            # FIXME: this is so slow now
                            status, i, num_bytes = self.parser._sim_atoi_inner(position, region, base=base, read_length=fmt_spec.length_spec)
                        except:
                            status = self.state.se.BoolS('failed')
                            i = self.state.se.Unconstrained('atoi', fmt_spec.size * 8)
                            num_bytes = 0
                        # increase failed count if we were unable to parse it
                        failed = self.parser.state.se.If(status, failed, failed + 1)
                        position += num_bytes
                    elif fmt_spec.spec_type == 'c':
                        if unreliable:
                            i = self.state.se.Unconstrained('char', 8)
                        else:
                            i = region.load(position, 1)
                            i = i.zero_extend(bits - 8)
                            position += 1
                    elif component.spec_type == 'n':
                        self.state.memory.store(args(argpos), self.state.se.BVS('format_%n', self.state.arch.bits))
                    else:
                        raise SimProcedureError("unsupported format spec '%s' in interpret" % fmt_spec.spec_type)
                    if not fmt_spec.discarded:
                        if fmt_spec.size * 8 < i.size():
                            i = self.parser.state.se.Extract(fmt_spec.size*8-1, 0, i)
                        elif fmt_spec.size * 8 > i.size():
                            if fmt_spec.spec_type == 'u':
                                i = self.parser.state.se.ZeroExt(fmt_spec.size * 8 - i.size(), i)
                            else:
                                i = self.parser.state.se.SignExt(fmt_spec.size * 8 - i.size(), i)
                        self.parser.state.memory.store(dest, i, size=fmt_spec.size, endness=self.parser.state.arch.memory_endness)

                argpos += 1

        if simfd is not None:
            simfd.read_data(position - addr)

        return (argpos - startpos) - failed

    def __repr__(self):
        outstr = ""
        for comp in self.components:
            outstr += (str(comp))

        return outstr

class FormatSpecifier(object):
    """
    Describes a format specifier within a format string.
    """

    def __init__(self, string, length_spec, size, signed, discarded=False):
        self.string = string
        self.size = size
        self.signed = signed
        self.length_spec = length_spec
        self.discarded = discarded

    @property
    def spec_type(self):
        return self.string[-1].lower()

    def __str__(self):
        return "%%%s" % self.string

    def __len__(self):
        return len(self.string)

class FormatParser(SimProcedure):
    """
    For SimProcedures relying on format strings.
    """

    # Basic conversion specifiers for format strings, mapped to sim_types
    # TODO: support for C and S that are deprecated.
    # TODO: We only consider POSIX locales here.
    basic_spec = {
        'd': 'int',
        'i': 'int',
        'o': 'unsigned int',
        'u': 'unsigned int',
        'x': 'unsigned int',
        'X': 'unsigned int',
        'e': 'double',
        'E': 'double',
        'f': 'double',
        'F': 'double',
        'g': 'double',
        'G': 'double',
        'a': 'double',
        'A': 'double',
        'c': 'char',
        's': 'char*',
        'p': 'uintptr_t',
        'n': 'uintptr_t', # pointer to num bytes written so far
        'm': None, # Those don't expect any argument
        '%': None, # Those don't expect any argument
    }

    # Signedness of integers
    int_sign = {
        'signed': ['d', 'i'],
        'unsigned' : ['o', 'u', 'x', 'X']
    }

    # Length modifiers and how they apply to integer conversion (signed / unsigned).
    int_len_mod = {
        'hh': ('char', 'uint8_t'),
        'h' : ('int16_t', 'uint16_t'),
        'l' : ('long', 'unsigned long'),
        # FIXME: long long is 64bit according to stdint.h on Linux,  but that might not always be the case
        'll' : ('int64_t', 'uint64_t'),

        # FIXME: intmax_t seems to be always 64 bit, but not too sure
        'j' : ('int64_t', 'uint64_t'),
        'z' : ('ssize', 'size_t'),
        't' : ('ptrdiff_t', 'ptrdiff_t'),
    }

    # Types that are not known by sim_types
    # Maps to (size, signedness)
    other_types = {
        ('string',): lambda _:(0, True) # special value for strings, we need to count
    }

    # Those flags affect the formatting the output string
    flags = ['#', '0', r'\-', r' ', r'\+', r'\'', 'I']

    @property
    def _mod_spec(self):
        """
        Modified length specifiers: mapping between length modifiers and conversion specifiers. This generates all the
        possibilities, i.e. hhd, etc.
        """
        mod_spec={}

        for mod, sizes in self.int_len_mod.iteritems():

            for conv in self.int_sign['signed']:
                mod_spec[mod + conv] = sizes[0]

            for conv in self.int_sign['unsigned']:
                mod_spec[mod + conv] = sizes[1]

        return mod_spec

    @property
    def _all_spec(self):
        """
        All specifiers and their lengths.
        """

        base = self._mod_spec

        for spec in self.basic_spec:
            base[spec] = self.basic_spec[spec]

        return base

    # Tricky stuff
    # Note that $ is not C99 compliant (but posix specific).

    def _match_spec(self, nugget):
        """
        match the string `nugget` to a format specifier.
        """
        # TODO: handle positional modifiers and other similar format string tricks.
        all_spec = self._all_spec


        # iterate through nugget throwing away anything which is an int
        # TODO store this in a size variable

        original_nugget = nugget
        length_str = [ ]
        length_spec = None
        discarded = False
        for j, c in enumerate(nugget):
            if c in ascii_digits:
                length_str.append(c)
            elif c == '*':
                discarded = True
            else:
                nugget = nugget[j:]
                length_spec = None if len(length_str) == 0 else int(''.join(length_str))
                break

        # we need the length of the format's length specifier to extract the format and nothing else
        length_spec_str_len = 0 if length_spec is None else len(length_str)
        discarded_len = 1 if discarded else 0
        # is it an actual format?
        for spec in all_spec:
            if nugget.startswith(spec):
                # this is gross coz sim_type is gross..
                nugget = nugget[:len(spec)]
                original_nugget = original_nugget[:(discarded_len + length_spec_str_len + len(spec))]
                nugtype = all_spec[nugget]
                try:
                    typeobj = sim_type.parse_type(nugtype).with_arch(self.state.arch)
                except:
                    raise SimProcedureError("format specifier uses unknown type '%s'" % repr(nugtype))
                return FormatSpecifier(original_nugget, length_spec, typeobj.size / 8, typeobj.signed, discarded)

        return None

    def _get_fmt(self, fmt):
        """
        Extract the actual formats from the format string `fmt`.

        :param list fmt: A list of format chars.
        :returns: a FormatString object
        """

        # iterate over the format string looking for format specifiers
        components = [ ]
        i = 0
        while i < len(fmt):
            if type(fmt[i]) is str and fmt[i] == "%":
                # FIXME: %% support
                if i + 1 < len(fmt) and type(fmt[i + 1]) is str and fmt[i + 1] == '%':
                    components.append('%')
                    i += 1
                # Note that we only support concrete format specifiers
                # grab the specifier
                # go to the space
                specifier = ""
                for c in fmt[i+1:]:
                    if type(c) is str:
                        specifier += c
                    else:
                        break

                specifier = self._match_spec(specifier)
                if specifier is not None:
                    i += len(specifier)
                    components.append(specifier)
                else:
                    # if we get here we didn't match any specs, the first char will be thrown away
                    # and we'll add the percent
                    i += 1
                    components.append('%')
            else:
                # claripy ASTs, which are usually symbolic variables
                # They will be kept as they are - even if those chars can be evaluated to "%"
                components.append(fmt[i])
            i += 1

        return FormatString(self, components)

    @timeout(seconds=10)
    def _sim_atoi_inner(self, str_addr, region, base=10, read_length=None):
        """
        Return the result of invoking the atoi simprocedure on `str_addr`.
        """

        from .. import SIM_PROCEDURES
        strtol = SIM_PROCEDURES['libc']['strtol']

        return strtol.strtol_inner(str_addr, self.state, region, base, True, read_length=read_length)


    def _sim_strlen(self, str_addr):
        """
        Return the result of invoking the strlen simprocedure on `str_addr`.
        """

        from .. import SIM_PROCEDURES
        strlen = SIM_PROCEDURES['libc']['strlen']

        return self.inline_call(strlen, str_addr).ret_expr


    def _parse(self, fmt_idx):
        """
        Parse format strings.

        :param fmt_idx: The index of the (pointer to the) format string in the arguments list.
        :returns:       A FormatString object which can be used for replacing the format specifiers with arguments or
                        for scanning into arguments.
        """

        fmtstr_ptr = self.arg(fmt_idx)

        if self.state.se.symbolic(fmtstr_ptr):
            raise SimProcedureError("Symbolic pointer to (format) string :(")

        length = self._sim_strlen(fmtstr_ptr)
        if self.state.se.symbolic(length):
            all_lengths = self.state.se.eval_upto(length, 2)
            if len(all_lengths) != 1:
                raise SimProcedureError("Symbolic (format) string, game over :(")
            length = all_lengths[0]

        if self.state.se.is_true(length == 0):
            return FormatString(self, [""])

        fmt_xpr = self.state.memory.load(fmtstr_ptr, length)

        fmt = [ ]
        for i in xrange(fmt_xpr.size(), 0, -8):
            char = fmt_xpr[i - 1 : i - 8]
            try:
                conc_char = self.state.solver.eval_one(char)
            except SimSolverError:
                # For symbolic chars, just keep them symbolic
                fmt.append(char)
            else:
                # Concrete chars are directly appended to the list
                fmt.append(chr(conc_char))

        # make a FormatString object
        fmt_str = self._get_fmt(fmt)

        l.debug("Fmt: %r", fmt_str)

        return fmt_str

from angr.errors import SimProcedureArgumentError, SimProcedureError, SimSolverError
