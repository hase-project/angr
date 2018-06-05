from .plugin import SimStatePlugin

HEAP_LOCATION = 0xc0000000
HEAP_SIZE = 64*4096

class SimStateLibc(SimStatePlugin):
    """
    This state plugin keeps track of various libc stuff:
    """

    #__slots__ = [ 'heap_location', 'max_str_symbolic_bytes' ]

    LOCALE_ARRAY = [
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x80
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x86
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x8c
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x92
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x98
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x9e
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xa4
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xaa
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xb0
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xb6
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xbc
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xc2
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xc8
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xce
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xd4
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xda
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xe0
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xe6
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xec
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xf2
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xf8
        b"\000\000", b"\000\000", b"\002\000", b"\002\000", b"\002\000", b"\002\000",  # 0xfe
        b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\003\040",  # 0x04
        b"\002\040", b"\002\040", b"\002\040", b"\002\040", b"\002\000", b"\002\000",  # 0x0a
        b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\002\000",  # 0x10
        b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\002\000",  # 0x16
        b"\002\000", b"\002\000", b"\002\000", b"\002\000", b"\001\140", b"\004\300",  # 0x1c
        b"\004\300", b"\004\300", b"\004\300", b"\004\300", b"\004\300", b"\004\300",  # 0x22
        b"\004\300", b"\004\300", b"\004\300", b"\004\300", b"\004\300", b"\004\300",  # 0x28
        b"\004\300", b"\004\300", b"\010\330", b"\010\330", b"\010\330", b"\010\330",  # 0x2e
        b"\010\330", b"\010\330", b"\010\330", b"\010\330", b"\010\330", b"\010\330",  # 0x34
        b"\004\300", b"\004\300", b"\004\300", b"\004\300", b"\004\300", b"\004\300",  # 0x3a
        b"\004\300", b"\010\325", b"\010\325", b"\010\325", b"\010\325", b"\010\325",  # 0x40
        b"\010\325", b"\010\305", b"\010\305", b"\010\305", b"\010\305", b"\010\305",  # 0x46
        b"\010\305", b"\010\305", b"\010\305", b"\010\305", b"\010\305", b"\010\305",  # 0x4c
        b"\010\305", b"\010\305", b"\010\305", b"\010\305", b"\010\305", b"\010\305",  # 0x52
        b"\010\305", b"\010\305", b"\010\305", b"\004\300", b"\004\300", b"\004\300",  # 0x58
        b"\004\300", b"\004\300", b"\004\300", b"\010\326", b"\010\326", b"\010\326",  # 0x5e
        b"\010\326", b"\010\326", b"\010\326", b"\010\306", b"\010\306", b"\010\306",  # 0x64
        b"\010\306", b"\010\306", b"\010\306", b"\010\306", b"\010\306", b"\010\306",  # 0x6a
        b"\010\306", b"\010\306", b"\010\306", b"\010\306", b"\010\306", b"\010\306",  # 0x70
        b"\010\306", b"\010\306", b"\010\306", b"\010\306", b"\010\306", b"\004\300",  # 0x76
        b"\004\300", b"\004\300", b"\004\300", b"\002\000", b"\000\000", b"\000\000",  # 0x7c
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x82
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x88
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x8e
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x94
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0x9a
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xa0
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xa6
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xac
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xb2
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xb8
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xbe
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xc4
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xca
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xd0
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xd6
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xdc
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xe2
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xe8
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xee
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xf4
        b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000", b"\000\000",  # 0xfa
        ]

    TOLOWER_LOC_ARRAY = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,         # 0x80
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,         # 0x88
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,         # 0x90
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,         # 0x98
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,         # 0xa0
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,         # 0xa8
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,         # 0xb0
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,         # 0xb8
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,         # 0xc0
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,         # 0xc8
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,         # 0xd0
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,         # 0xd8
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,         # 0xe0
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,         # 0xe8
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,         # 0xf0
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xffffffff,   # 0xf8
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,         # 0x00
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,         # 0x08
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,         # 0x10
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,         # 0x18
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,         # 0x20
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,         # 0x28
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,         # 0x30
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,         # 0x38
        0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,         # 0x40
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,         # 0x48
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,         # 0x50
        0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,         # 0x58
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,         # 0x60
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,         # 0x68
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,         # 0x70
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,         # 0x78
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,         # 0x80
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,         # 0x88
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,         # 0x90
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,         # 0x98
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,         # 0xa0
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,         # 0xa8
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,         # 0xb0
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,         # 0xb8
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,         # 0xc0
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,         # 0xc8
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,         # 0xd0
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,         # 0xd8
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,         # 0xe0
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,         # 0xe8
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,         # 0xf0
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,         # 0xf8
    ]


    TOUPPER_LOC_ARRAY =[
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,         # 0x80
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,         # 0x88
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,         # 0x90
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,         # 0x98
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,         # 0xa0
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,         # 0xa8
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,         # 0xb0
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,         # 0xb8
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,         # 0xc0
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,         # 0xc8
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,         # 0xd0
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,         # 0xd8
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,         # 0xe0
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,         # 0xe8
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,         # 0xf0
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xffffffff,   # 0xf8
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,         # 0x00
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,         # 0x08
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,         # 0x10
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,         # 0x18
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,         # 0x20
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,         # 0x28
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,         # 0x30
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,         # 0x38
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,         # 0x40
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,         # 0x48
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,         # 0x50
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,         # 0x58
        0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,         # 0x60
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,         # 0x68
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,         # 0x70
        0x58, 0x59, 0x5a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,         # 0x78
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,         # 0x80
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,         # 0x88
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,         # 0x90
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,         # 0x98
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,         # 0xa0
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,         # 0xa8
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,         # 0xb0
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,         # 0xb8
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,         # 0xc0
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,         # 0xc8
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,         # 0xd0
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,         # 0xd8
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,         # 0xe0
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,         # 0xe8
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,         # 0xf0
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,         # 0xf8
    ]

    def __init__(self):
        SimStatePlugin.__init__(self)

        # various thresholds
        self.heap_location = HEAP_LOCATION
        self.mmap_base = HEAP_LOCATION + HEAP_SIZE * 2
        self.buf_symbolic_bytes = 60
        self.max_symbolic_strstr = 1
        self.max_symbolic_strchr = 16
        self.max_variable_size = 128
        self.max_str_len = 128
        self.max_buffer_size = 48
        self.max_strtol_len = 11 # len(str(2**31)) + 1
        self.max_memcpy_size = 4096
        self.max_packet_size = 256
        self.exit_handler = []

        # strtok
        self.strtok_heap = [ ]
        self.simple_strtok = True
        self.strtok_token_size = 1024

        # helpful stuff
        self.strdup_stack = [ ]

        # as per Audrey:
        # the idea is that there's two abi versions, and for one of them, the
        # address passed to libc_start_main isn't actually the address of the
        # function, but the address of a pointer to a struct containing the
        # actual function address and the table of contents address
        self.ppc64_abiv = None

        # It will be initialized in __libc_start_main SimProcedure
        self.ctype_b_loc_table_ptr = None
        self.ctype_tolower_loc_table_ptr = None
        self.ctype_toupper_loc_table_ptr = None

        self._errno_location = None

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        c = SimStateLibc()
        c.heap_location = self.heap_location
        c.mmap_base = self.mmap_base
        c.buf_symbolic_bytes = self.buf_symbolic_bytes
        c.max_symbolic_strstr = self.max_symbolic_strstr
        c.max_symbolic_strchr = self.max_symbolic_strchr
        c.max_variable_size = self.max_variable_size
        c.max_str_len = self.max_str_len
        c.max_buffer_size = self.max_buffer_size
        c.max_strtol_len = self.max_strtol_len
        c.max_memcpy_size = self.max_memcpy_size
        c.strtok_heap = self.strtok_heap[:]
        c.simple_strtok = self.simple_strtok
        c.strtok_token_size = self.strtok_token_size
        c.strdup_stack = self.strdup_stack[:]
        c.ppc64_abiv = self.ppc64_abiv
        c.ctype_b_loc_table_ptr = self.ctype_b_loc_table_ptr
        c.ctype_tolower_loc_table_ptr = self.ctype_tolower_loc_table_ptr
        c.ctype_toupper_loc_table_ptr = self.ctype_toupper_loc_table_ptr
        c._errno_location = self._errno_location
        c.exit_handler = self.exit_handler
        #c.aa = self.aa

        return c

    def _combine(self, others):
        new_heap_location = max(o.heap_location for o in others)
        if self.heap_location != new_heap_location:
            self.heap_location = new_heap_location
            return True
        else:
            return False

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

    def init_state(self):
        if o.ABSTRACT_MEMORY in self.state.options:
            return

        try:
            self.state.memory.permissions(HEAP_LOCATION)
        except SimMemoryError:
            self.state.memory.map_region(HEAP_LOCATION, 4096*64, 3)


from angr.sim_state import SimState
SimState.register_default('libc', SimStateLibc)

from ..errors import SimMemoryError
from .. import sim_options as o
